# Changelog

All notable changes to this project are recorded here. The format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and this project
intends to follow [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

Rule ids are part of the public interface. Renaming one, changing its severity,
or moving a rule into or out of the waivable set is a breaking change and is
recorded here.

## [Unreleased]

### Added

- `auditHeaders()` and the `http-security-header-auditor` binary: evaluate a
  captured set of HTTP response header fields against a declared policy and its
  route exceptions.
- Fifty-three rules covering required and forbidden fields, allowed values,
  `Content-Security-Policy` directives and contradictions,
  `Strict-Transport-Security` duration and tokens, route exceptions, document
  shape, limits and vacuity.
- `Content-Security-Policy-Report-Only` is recognised and never counted as a
  policy in force; `csp-report-only-without-enforcement` explains why a route
  that looks protected is not.
- Route exceptions with a mandatory reason and a mandatory expiry, compared
  against an injected `--as-of` date. Without one, no waiver is applied and the
  run is `incomplete`.
- Ten enforced limits, each reported by name when reached.
- Examples that exit 0, 1 and 2.

### Security

- No network of any kind: no fetch, no host resolution, no endpoint discovery,
  no scanning. The capture schema has nowhere to put an address, and
  `test/no-network.test.mjs` proves the property four independent ways.
- Every untrusted string reaching output is stripped of C0, DEL, C1, U+2028,
  U+2029 and the bidi controls, and bounded.
- A waiver can excuse a verdict about a response and can never excuse a gap in
  the evidence.
- A parse failure does not quote the file it failed on. V8 writes
  `Unexpected token 'A', "AKIAIOSFODNN7EXAMPLE" is not valid JSON`, and
  `input-not-json` interpolated that message, so a capture short enough to be
  nothing but a credential was reproduced in full on stdout -- the one string
  reaching output that stripping and bounding could not contain, since `excerpt`
  cuts from the end and the quoted span is at the front. The finding now carries
  the position, line, column and offending token and never the text at them, and
  `test/parse-failure-redaction.test.mjs` drives the published placeholder
  through the real binary and asserts it absent from stdout, from stderr and
  from every prefix down to eight characters.

No release has been published.
