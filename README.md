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
pfSense ──syslog/UDP 514──▶ Syslog Receiver ─▶ Parser ─▶ SQLite ─▶ Detection ─▶ Alerts (stdout)
                                                                   ├─ threshold rules
                                                                   ├─ statistical baselines
                                                                   └─ rule-to-log correlation
```

## Layout

```
src/
  main.py              # entry point, wires everything together
  syslog_server.py     # async UDP syslog receiver
  parsers/             # log-line parsers (pfSense filterlog; pihole stub)
  ruleset/             # pfSense config.xml parser + rules.yaml read/write
  storage/             # SQLite storage + baselines
  detection/           # rules.py, statistical.py, correlation.py
  alerts/              # alert model + stdout alerter
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
    alert_on_no_match: true
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
**Home Assistant** (which then notifies your phone via its mobile app), enable
the webhook alerter in `settings.yaml`:

```yaml
alerts:
  stdout: true
  homeassistant:
    enabled: true
    webhook_url: "http://192.168.1.220:8123/api/webhook/netmon_alert"
    min_severity: "critical"   # info | warning | critical
```

In Home Assistant: **Settings → Automations → Create → trigger "Webhook"** (set
the ID to match the URL, e.g. `netmon_alert`), then an action that notifies you:

```yaml
trigger:
  - platform: webhook
    webhook_id: netmon_alert
action:
  - service: notify.mobile_app_your_phone
    data:
      title: "{{ trigger.json.title }}"
      message: "{{ trigger.json.message }}"
```

The POST body (`trigger.json`) also includes `severity`, `rule_name`, and
`details`. `min_severity: critical` pushes only genuine security gaps (traffic
that passed when a rule says block); everything still lands in the logs.

## pfSense setup

Status → System Logs → Settings → enable Remote Logging, set the remote log
server to `docker-host-ip:514`, and forward at least the Firewall logs.

## Roadmap

- Phase 4: Pi-hole DNS log integration and DNS/firewall correlation.
- Interface groups and floating-rule ordering (currently approximated by
  document order; per-interface first-match is handled).
- Additional alert channels (email, Pushover, Discord).
