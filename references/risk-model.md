# SkillGuard risk model

SkillGuard produces a deterministic static-analysis score. The score is intended to be conservative and explainable, not a probability that a skill is malicious.

## Finding weights

| Severity | Weight |
| --- | ---: |
| CRITICAL | 50 |
| HIGH | 25 |
| MEDIUM | 10 |
| LOW | 5 |
| INFO | 0 |

A finding in a file that SkillGuard classifies as executable is multiplied by `1.3`. This reflects the higher impact of executable behavior compared with prose that may not be followed.

## Severity floors

A maximum-severity floor prevents a single severe finding from being averaged down by many low findings:

| Highest finding | Minimum score |
| --- | ---: |
| CRITICAL | 81 |
| HIGH | 51 |
| MEDIUM | 21 |
| LOW | 0 |

The final score is clamped to `0..100`.

## Recommendations

| Condition | Recommendation |
| --- | --- |
| Any critical or high finding | `DO NOT INSTALL` |
| Medium findings only | `CAUTION` |
| No findings, full coverage | `SAFE` |
| No findings, partial coverage | `CAUTION` |

`safe_to_install` is true only for `SAFE` with full coverage.

## Coverage

Coverage is `full` only when:

- A `SKILL.md` was found and read.
- No file was skipped for size, limits, or read errors.
- No source file failed to parse.
- No requested online lookup failed.
- The file-count and total-size limits were not reached.

Binary document assets such as images and fonts do not by themselves reduce coverage. Unknown binary files do.

## Deduplication and truncation

Findings are deduplicated by `(rule_id, file, line)`. The score is calculated from all deduplicated findings. The returned report is capped at 500 findings by default; `summary.truncated` and `summary.total` disclose the difference.

## Non-goals

SkillGuard does not execute the target, prove intent, detect every obfuscation scheme, or replace human review. A clean report is a statement about the configured rules and reviewed coverage.
