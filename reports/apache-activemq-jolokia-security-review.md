# Apache ActiveMQ Classic Jolokia Security Review

## Executive Summary

This case study reviews the management boundary between Apache ActiveMQ
Classic, Jolokia, JMX MBeans, transport URI parsing, and dynamic broker
creation. It focuses on the source paths and patch evolution associated with
CVE-2026-34197 and its later bypass, CVE-2026-40466.

The review compares upstream Apache ActiveMQ tags `activemq-6.2.2`,
`activemq-6.2.3`, and `activemq-6.2.5`. It shows why validating only the
immediately supplied URI scheme was insufficient when later components could
resolve or return another transport URI.

No exploit script, executable payload, malicious Spring configuration, or
public-target testing material is included.

## Project and Scope

| Area | Detail |
|---|---|
| Project | Apache ActiveMQ Classic |
| Upstream | `apache/activemq` |
| Language | Java |
| Compared releases | 6.2.2, 6.2.3, 6.2.5 |
| Primary boundary | Jolokia request to JMX operation to transport creation |
| Primary classes | `BrokerView`, `VMTransportFactory`, URI support and broker factory paths |
| Configuration | Default `jolokia-access.xml` |

## Review Method

1. Confirm the management operations exposed through the ActiveMQ MBean.
2. Trace attacker-controlled connector strings into transport parsing.
3. Identify secondary configuration and broker-creation paths.
4. Compare the first patch with the later bypass fix.
5. Review regression tests for expected parser behavior.
6. Separate direct validation from downstream resolution and side effects.

## Management Boundary

The default Jolokia configuration restricts general commands but allows all
operations on MBeans matching `org.apache.activemq:*`. The broker MBean
provides operations that dynamically add transport and network connectors.

This creates a high-impact trust transition:

```text
Authenticated HTTP management request
  -> Jolokia operation dispatch
  -> ActiveMQ BrokerView MBean
  -> connector URI parsing
  -> transport factory selection
  -> optional dynamic broker configuration
```

Authentication reduces exposure, but an authenticated management user should
not automatically gain a path to arbitrary JVM code execution.

## Root-Cause Review

### 1. Dynamic Connector Operations Accepted Untrusted URI Structure

In ActiveMQ 6.2.2, `BrokerView.addConnector(String)` and
`BrokerView.addNetworkConnector(String)` pass the supplied discovery address
into broker services without a transport-scheme security check.

The issue is not simply that a URI is user-controlled. ActiveMQ supports
composite and nested transport URIs, so security decisions must account for
every effective component after parsing and resolution.

### 2. VM Transport Could Create a Broker from a Secondary Configuration URI

`VMTransportFactory.doCompositeConnect()` parses VM transport options and
removes the `brokerConfig` value. When a named broker does not already exist,
the resulting configuration URI can be passed to `BrokerFactory.createBroker`.

The security-sensitive transition is:

```text
transport URI
  -> VM transport options
  -> brokerConfig URI
  -> BrokerFactory implementation
  -> application-context construction
```

The official advisory explains that a remote Spring XML application context
could instantiate singleton beans before later broker configuration
validation rejected the setup. Validation after object construction is too
late when construction itself has side effects.

## Patch Evolution

### ActiveMQ 6.2.3: Entry-Point Scheme Validation

The first fix added `validateAllowedUrl()` calls to both dynamic connector
operations in `BrokerView`. The validator:

- Parses the supplied URI.
- Recursively visits composite URI components.
- Rejects the `vm` transport scheme.
- Limits recursive nesting depth.

This directly blocks the original path when the dangerous VM scheme is visible
in the submitted URI.

### Why the First Fix Was Incomplete

The first patch made its decision at the initial MBean input boundary. A
transport such as HTTP Discovery can retrieve a second-stage URI from another
resource. If the returned value introduces a VM transport, the dangerous
scheme is not present in the original string inspected by `BrokerView`.

This is a general time-of-check versus later-resolution problem:

```text
initial URI passes validation
  -> discovery transport resolves external data
  -> second-stage URI introduces a denied transport
  -> downstream component processes the new URI
```

The Apache advisory for CVE-2026-40466 confirms that this behavior could bypass
the CVE-2026-34197 fix when the HTTP transport module was available.

### ActiveMQ 6.2.5: Broader Denylist and Sink-Level Control

The later hardening expanded `BrokerView.DENIED_TRANSPORT_SCHEMES` beyond
`vm`, including discovery and fan-out mechanisms that can transform or resolve
additional transport values. It also corrected component validation in
composite URIs and added tests for nested forms.

More importantly, `VMTransportFactory` added a broker-creation scheme
allowlist. The default permits only `broker` and `properties`; XBean-based
broker creation is disabled unless an administrator explicitly enables it
through a system property.

This moves protection closer to the dangerous operation:

```text
secondary broker configuration URI
  -> VMTransportFactory scheme allowlist
  -> broker creation only when explicitly permitted
```

Sink-level validation is stronger because it applies regardless of which
upstream transport or parser produced the secondary URI.

## Security Findings

### A-01: Overly Powerful Jolokia MBean Operation Surface

**Severity:** High  
**CWE:** CWE-284, Improper Access Control

The default policy grants all operations to the broad
`org.apache.activemq:*` MBean namespace. This includes operations capable of
changing network topology and initiating transport processing.

**Recommendation**

- Expose only management operations required by the deployment.
- Restrict Jolokia to dedicated administrative networks.
- Use separate, least-privileged management identities.
- Monitor dynamic connector creation and configuration changes.

### A-02: Validation Before URI Resolution

**Severity:** Important  
**CWE:** CWE-20, Improper Input Validation

The first patch validated the original string but not every later value
produced by discovery or nested transport processing.

**Recommendation**

- Revalidate security properties after every transformation or resolution.
- Prefer a positive list of permitted transport capabilities.
- Treat remote discovery responses as untrusted input.

### A-03: Side Effects During Configuration Construction

**Severity:** Important  
**CWE:** CWE-94, Improper Control of Generation of Code

The vulnerable path allowed application-context construction to instantiate
objects before the configuration was rejected. Parser or schema validation
that occurs after object creation cannot prevent constructor, factory-method,
or initialization side effects.

**Recommendation**

- Reject untrusted configuration schemes before selecting a factory.
- Avoid remote executable configuration formats in management-triggered code.
- Separate parsing and validation from object instantiation.

## Regression-Test Review

The later upstream tests cover:

- Direct denied transport schemes.
- Composite connector URIs.
- Nested composite URIs.
- Composite forms without optional parentheses.
- Maximum nesting depth.
- Default rejection and explicit opt-in for broker factory schemes.

These tests are valuable because transport grammar, not only individual
strings, defines the attack surface.

## Defensive Detection Opportunities

- Alert on Jolokia `exec` requests invoking connector-management operations.
- Monitor creation of network connectors outside approved change windows.
- Detect broker JVM outbound HTTP requests to new or untrusted destinations.
- Review logs for rejected transport schemes and broker-creation schemes.
- Restrict broker egress so management activity cannot retrieve arbitrary
  remote configuration.

## Limitations

- This report is a focused management-boundary and patch-diff review, not a
  complete audit of every ActiveMQ module.
- Controlled reproduction was performed separately; offensive automation and
  payload material are intentionally excluded here.
- Deployment-specific authentication, reverse proxies, classpaths, and egress
  policies can change practical exposure.

## Engineering Lessons

1. Validate at the dangerous sink, not only at the first entry point.
2. Revalidate values created by discovery, redirects, parsers, and adapters.
3. URI security reviews must model composite grammar and nested resolution.
4. Broad administrative namespaces can expose operations with very different
   risk levels.
5. Patch review should test alternate paths to the same sink, not only the
   originally reported input.

## References

- [Apache ActiveMQ source repository](https://github.com/apache/activemq)
- [Apache advisory for CVE-2026-34197](https://activemq.apache.org/security-advisories.data/CVE-2026-34197-announcement.txt)
- [Apache advisory for CVE-2026-40466](https://activemq.apache.org/security-advisories.data/CVE-2026-40466-announcement.txt)
- [Apache ActiveMQ Classic security advisories](https://activemq.apache.org/components/classic/security)

