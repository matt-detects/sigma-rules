# Detection Engineering Lab Notes — February to March 3 Updates: Cross-Platform Persistence Followed by C2 Callback Lab

## Sigma Rules & Elastic Correlation

### Correctness Fixes (High Impact)

The original rules were examined in the context of deeper study and determined to contain bugs that would have caused zero detections in
production, not reduced effectiveness, but complete failure:

- **Broken filter logic** (`or not filter_benign_examples`) would have fired on
  almost everything or suppressed almost everything depending on the backend
- **Wrong field name on EID 20** (`CommandLine` vs `Destination`) meant the core
  WMI consumer rule would have produced no matches against real Sysmon logs
- These were correctness issues, not quality gaps — the rules would have passed
  review and then silently failed in deployment

### Substantive Additions (High Impact)

- **EID 19 rule** completes the detection chain. Without it, filter creation
  (the first of three steps) goes undetected entirely. It is also the earliest
  warning signal and the most useful for proactive hunting
- **Dual field matching on EID 20** (`CommandLine` + `Destination`) was directly
  validated by the observed attack logs. Without this fix the rule would miss every
  real event
- **Elastic EQL correlation** is a capability step rather than a rule quality
  improvement. Seven individual alerts of varying confidence become one
  causally-linked, two-stage, same-host signal with near-zero false positive rate
- **Cross-platform coverage** (Windows WMI + Linux systemd both feeding EQL
  Stage 1) means the correlation fires regardless of which platform the attacker
  targets, without separate correlation logic per OS

### Incremental Improvements (Medium Impact)

- False positive tuning and filter splitting make rules more mature and production-ready
- Name keyword additions (`Check`, `Windows`) grounded in confirmed observed
  attack telemetry
- A competent analyst would have caught most of these during a deployment review

### Caveats

- **IOC-anchored rules are perishable** — `10.10.10.101` will rotate. The
  structural value is the pattern (Value List → Indicator Match rule) not the
  specific IP. This is reflected as a future improvement in the Elastic / Kibana correlation documentation in this repository.

---

## Summary

| Area | Starting Point | Improvement Type | Impact |
|------|---------------|-----------------|--------|
| Sigma filter logic | Functionally broken | Correctness fix | High |
| Sigma EID 20 field name | Produced zero matches | Correctness fix | High |
| EID 19 rule | Missing entirely | New capability | High |
| Elastic EQL correlation | Missing entirely | New capability | High |
| Cross-platform coverage | Windows only | New capability | High |
| IOC rules | Missing entirely | New capability | Medium (perishable) |
