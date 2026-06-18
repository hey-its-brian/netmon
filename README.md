# netmon — Log-O-Matic

A lightweight, local-first network log monitor for a homelab. It ingests pfSense
firewall logs (live via syslog, or by replaying a log file), stores them in
SQLite, and raises alerts on anomalies using three complementary detectors.

## Detection

| Detector | What it does |
|----------|--------------|
| **Threshold rules** | Hard limits: high block volume from one IP, port scans, connections to suspicious ports. |
| **Statistical baselines** | Learns hourly/daily norms (connection counts, block ratio) over a learning period, then alerts on deviations beyond N standard deviations. |
| **Rule-to-log correlation** | Compares live traffic against your *actual* pfSense ruleset and flags `action_mismatch` (the governing rule says one thing, traffic did another) and `no_matching_rule` (traffic governed by no rule). The matcher replicates pfSense's evaluation: first-match ordering, alias expansion (host/network/port), CIDR + interface network keywords (`lan`/`lanip`/`(self)`), negation, port ranges, and combined `tcp/udp`. When a rule references something it can't resolve, it stays silent rather than guess. Ported/extended from the `yalt_inspector` project. |

## Architecture

```
pfSense ──syslog/UDP 514──▶ Syslog Receiver ─▶ Parser ─▶ SQLite ─▶ Detection ─▶ Alerts
                                                                   ├─ threshold rules        ├─ stdout (logs)
                                                                   ├─ statistical baselines  ├─ JSONL (dashboards)
                                                                   └─ rule-to-log correlation └─ MQTT → Home Assistant
                                                                                                  (auto-discovery)
```

## Layout

```
src/
  main.py              # entry point, wires everything together
  syslog_server.py     # async UDP syslog receiver
  parsers/             # log-line parsers (pfSense filterlog; pihole stub)
  ruleset/             # pfSense config.xml parser + rules.yaml read/write
  storage/             # SQLite storage + baselines
  detection/           # rules.py, statistical.py, correlation.py, matcher.py
  alerts/              # alert model + stdout, JSONL, and MQTT (HA) alerters
  tools/               # extract_pfsense.py (config.xml -> rules.yaml)
settings.yaml          # hand-edited app settings
rules.yaml             # GENERATED firewall rules + interface map (gitignored)
samples/
  example_config.xml   # synthetic pfSense config for tests/demos
  example_rules.yaml   # synthetic generated ruleset for tests/demos
```

## Configuration: two files

- **`settings.yaml`** — hand-edited basics (syslog, storage, detection thresholds,
  alerts). This is the file you tune.
- **`rules.yaml`** — *generated*, sanitized extract of your pfSense firewall rules
  + interface map. The full `config.xml` backup (which contains secrets) never
  needs to touch the running app — you extract just what correlation needs.

Generate / refresh `rules.yaml` from a pfSense `config.xml` backup:

```bash
python -m src.tools.extract_pfsense pfsense-config.xml -o rules.yaml
```

This is designed to be driven by an automated backup pipeline:

```
[backup tool] -> config.xml -> extract_pfsense -> rules.yaml -> restart netmon
```

Correlation reads `rules.yaml` at startup, so restart the container after
regenerating it. Enable it in `settings.yaml`:

```yaml
detection:
  correlation:
    enabled: true
    ruleset_path: "/config/rules.yaml"
    alert_on_no_match: false   # default-deny is noisy; action_mismatch is the high-signal alert
```

## Setup

The repo ships **templates**, not your real config. After cloning:

```bash
cp settings.example.yaml settings.yaml        # then tune to taste
cp rules.example.yaml rules.yaml              # placeholder until you extract real rules
python3 -m src.tools.extract_pfsense pfsense-config.xml -o rules.yaml   # real ruleset
```

`settings.yaml` and `rules.yaml` are gitignored — they stay local. `docker compose`
mounts both into the container, so they must exist before `docker compose up`.

### Storage

Logs go into SQLite and are bounded by retention (hourly cleanup), so the DB
plateaus rather than growing forever:

```yaml
storage:
  retention_days: 30   # delete logs older than this
  store_raw: true      # keep the full raw log line per row; false ~halves storage
```

SQLite doesn't auto-shrink after deletes — lowering these caps new growth but a
one-time `VACUUM` is needed to reclaim existing file size.

## Usage

Run live (listens on syslog UDP 514):

```bash
python -m src.main settings.yaml
```

Replay an existing pfSense log through the full pipeline (no live feed needed):

```bash
python -m src.main settings.yaml --replay samples/filter.log
```

Run the tests:

```bash
python -m unittest discover -s tests
```

## Alerting

Alerts always print to stdout (`docker compose logs`). To also push them to
**Home Assistant**, enable the MQTT alerter in `settings.yaml`:

```yaml
alerts:
  stdout: true
  mqtt:
    enabled: true
    host: "192.168.1.220"      # your MQTT broker (often the HA host running Mosquitto)
    port: 1883
    username: ""               # optional
    password: ""
    base_topic: "netmon"
    discovery_prefix: "homeassistant"
    min_severity: "info"       # info | warning | critical
```

netmon uses **MQTT Discovery**, so it advertises its own entities — HA wires
itself up with no manual config. After enabling, a `netmon` device appears in
**Settings → Devices & Services → MQTT** with two entities:

| Entity | What it is |
|--------|------------|
| `event.netmon_alert` | Fires once per alert. `event_type` is the severity (`info`/`warning`/`critical`); `rule_name`, `message`, and `details` ride along as attributes. Trigger automations off this. |
| `sensor.netmon_last_alert` | The most recent alert message, with severity/rule/details as attributes. Retained, so it survives restarts — good for dashboards. |

An MQTT Last-Will keeps both entities accurate: if netmon stops, the broker
publishes `offline` to `netmon/status` and HA shows them **unavailable**.

To get a phone push on real security gaps, add an HA automation that triggers on
the event entity and filters by `event_type`:

```yaml
trigger:
  - platform: state
    entity_id: event.netmon_alert
condition:
  - condition: template
    value_template: "{{ trigger.to_state.attributes.event_type == 'critical' }}"
action:
  - service: notify.mobile_app_your_phone
    data:
      title: "netmon: {{ trigger.to_state.attributes.rule_name }}"
      message: "{{ trigger.to_state.attributes.message }}"
```

`min_severity` gates what netmon publishes at all; filtering by `event_type` in
the automation is what decides which alerts actually buzz your phone. Everything
still lands in the logs regardless.

**Prerequisite:** an MQTT broker (e.g. the Mosquitto add-on) and HA's **MQTT
integration** must be set up. netmon publishes to the broker; HA reads from it.

**Severity of `action_mismatch` is directional:**

- **CRITICAL** — traffic *passed* when a rule expects *block* (something got
  through that shouldn't have — a security gap).
- **WARNING** — traffic was *blocked* when a rule expects *pass* (over-blocking;
  more secure than configured, usually a connectivity issue).

## pfSense setup

Status → System Logs → Settings → enable Remote Logging, set the remote log
server to `docker-host-ip:514`, and forward at least the Firewall logs.

## Roadmap

- Phase 4: Pi-hole DNS log integration and DNS/firewall correlation.
- Interface groups and floating-rule ordering (currently approximated by
  document order; per-interface first-match is handled).
- Additional alert channels (email, Pushover, Discord).
