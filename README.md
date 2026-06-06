# Code Audit Case Studies

Defensive source-code security reviews with an emphasis on traceable evidence,
false-positive reduction, and actionable remediation.

## Published Case Study

### [Apache ActiveMQ Classic Jolokia Security Review](reports/apache-activemq-jolokia-security-review.md)

The review compares upstream ActiveMQ 6.2.2, 6.2.3, and 6.2.5 to analyze the
Jolokia-to-JMX management boundary, nested transport URI handling, dynamic
broker creation, the initial CVE-2026-34197 fix, and the later CVE-2026-40466
bypass hardening.

## Audit Approach

1. Establish the application architecture and trust boundaries.
2. Enumerate routes, authentication filters, and authorization checks.
3. Trace high-impact sinks back to attacker-controlled sources.
4. Review dangerous features from the entry point toward the sink.
5. Inspect framework and dependency behavior when source-level evidence is
   incomplete.
6. Separate confirmed findings, constrained findings, and false positives.
7. Provide root-cause remediation rather than payload-specific blocking.

The reusable checklist is available in
[`methodology/java-web-audit-checklist.md`](methodology/java-web-audit-checklist.md).

## Publication Policy

- No customer systems, credentials, private infrastructure, or asset lists.
- No automated exploitation or mass-scanning code.
- Validation examples are intentionally minimal and intended for local,
  authorized test environments.
- Findings should be coordinated with the relevant maintainer before detailed
  publication when the affected version remains supported.

## Skills Demonstrated

`Java` | `Apache ActiveMQ` | `Jolokia` | `JMX` | `Patch Diffing` |
`Data-Flow Analysis` | `URI Parser Review` | `Remediation Design`
