# netmon — Log-O-Matic

A lightweight, local-first network log monitor for a homelab. It ingests pfSense
firewall logs (live via syslog, or by replaying a log file), stores them in
SQLite, and raises alerts on anomalies using three complementary detectors.

## Detection

| Detector | What it does |
|----------|--------------|
| **Threshold rules** | Hard limits: high block volume from one IP, port scans, connections to suspicious ports. |
| **Statistical baselines** | Learns hourly/daily norms (connection counts, block ratio) over a learning period, then alerts on deviations beyond N standard deviations. |
| **Rule-to-log correlation** | Compares live traffic against your *actual* pfSense ruleset (parsed from a `config.xml` backup) and flags `action_mismatch` (rule says one thing, traffic did another) and `no_matching_rule` (traffic governed by no rule). Ported from the `yalt_inspector` project. |

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
  ruleset/             # pfSense config.xml firewall-rule parser
  storage/             # SQLite storage + baselines
  detection/           # rules.py, statistical.py, correlation.py
  alerts/              # alert model + stdout alerter
samples/
  example_config.xml   # synthetic pfSense ruleset for tests/demos
```

## Usage

Run live (listens on syslog UDP 514):

```bash
python -m src.main config.yaml
```

Replay an existing pfSense log through the full pipeline (no live feed needed):

```bash
python -m src.main config.yaml --replay samples/filter.log
```

Run the tests:

```bash
python -m unittest discover -s tests
```

## Configuration

See `config.yaml`. To enable rule-to-log correlation, point it at a pfSense
config backup:

```yaml
detection:
  correlation:
    enabled: true
    config_path: "/data/config.xml"   # your pfSense config.xml backup
    alert_on_no_match: true
```

## pfSense setup

Status → System Logs → Settings → enable Remote Logging, set the remote log
server to `docker-host-ip:514`, and forward at least the Firewall logs.

## Roadmap

- Phase 4: Pi-hole DNS log integration and DNS/firewall correlation.
- Interface-name mapping (logical `lan`/`wan` ↔ device `igb1.20`) to tighten
  correlation matching.
- Additional alert channels (email, Pushover, Discord).
