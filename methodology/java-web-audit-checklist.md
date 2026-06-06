# Java Web Audit Checklist

## 1. Scope and Architecture

- Record the exact version, commit, build system, JDK, and framework versions.
- Identify controllers, filters, interceptors, templates, mappers, scheduled
  jobs, message consumers, and administrative interfaces.
- Draw trust boundaries between anonymous, authenticated, administrative, and
  internal-only functionality.

## 2. Authentication and Authorization

- Enumerate every route and its effective authentication policy.
- Check whether security filters cover alternate prefixes and HTTP methods.
- Review object-level authorization after database lookups.
- Verify that administrative service methods cannot be reached through a
  weaker public controller.

## 3. Injection Sinks

- SQL: raw statements, string interpolation, dynamic table or column names.
- OS commands: `Runtime.exec`, `ProcessBuilder`, scripts, and converters.
- Templates and expressions: FreeMarker, SpEL, OGNL, MVEL, and JSP EL.
- Directory services: LDAP filters and JNDI lookups.
- Logging and response splitting: attacker-controlled format strings or
  headers.

## 4. Files and Archives

- Upload extension, MIME, magic-byte, storage-path, and execution controls.
- Path normalization before read, write, move, delete, and archive extraction.
- ZIP Slip, symbolic links, decompression limits, and nested archives.
- Download authorization and indirect object reference checks.

## 5. Server-Side Requests

- Scheme allowlist and URL parsing consistency.
- DNS resolution and private, loopback, link-local, multicast, and reserved
  address blocking.
- Redirect revalidation after every hop.
- Proxy behavior, alternate IP representations, and DNS rebinding resistance.

## 6. Serialization and Parsing

- Java native serialization and dangerous gadget-capable libraries.
- Polymorphic JSON or XML deserialization.
- XML external entities and unsafe XSLT.
- Parser size, recursion, and entity expansion limits.

## 7. Configuration and Dependencies

- Debug responses, exposed API documentation, weak defaults, and sample keys.
- Dependency versions and security-relevant configuration.
- Database privileges and dangerous connection options.
- Production differences from development profiles.

## 8. Finding Quality

For each candidate finding, record:

- Source, transformations, sink, and effective security controls.
- Required privileges and deployment conditions.
- Minimal local validation procedure.
- Confirmed impact and important limitations.
- Root-cause fix, defense in depth, and a regression test.

Classify rejected hypotheses explicitly. Demonstrating why a suspected issue is
not exploitable is part of a high-quality audit.

