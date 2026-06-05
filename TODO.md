# TODO

Deferred findings from the 2026-06-05 performance/bug audit. None are blocking;
the critical CPU fix and the clock-skew / stats-ordering / match-rule fixes
already landed. These are the "found but not fixed" items.

## Detection robustness

- [ ] **Threshold alert latch** (`src/detection/rules.py`)
  `_check_blocked_threshold` / `_check_port_scan` fire on `count == threshold`
  rather than a real per-IP latch. With a sliding window this re-alerts every
  time the count re-crosses the threshold, and depends on the count landing
  exactly on the boundary. Replace with a per-IP "already alerted" latch plus a
  cooldown so each incident alerts once.

- [ ] **Floating / `quick` rule semantics** (`src/detection/matcher.py` +
  `src/ruleset/pfsense.py`)
  The matcher treats every rule as first-match in document order. In real
  pfSense, floating rules without `quick` are *last*-match, and `quick` is not
  captured by the extractor at all. Verdicts can be wrong on configs that rely
  on floating rules. Capture `<quick>` during extract and model floating vs.
  per-interface evaluation order.

## Lower priority / informational

- [ ] **IPv6 traffic is dropped** (`src/parsers/pfsense.py` returns `None` for
  IP version 6). No v6 traffic is monitored. Implement v6 parsing if needed.

- [ ] **HA alerter threading** (`src/alerts/homeassistant.py`) spawns one daemon
  thread per alert: in-flight pushes can be lost on shutdown, and an alert storm
  spawns unbounded threads. Consider a small worker queue.
