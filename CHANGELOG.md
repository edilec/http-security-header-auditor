# Changelog

All notable changes to this project are recorded here. The format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and this project
intends to follow [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

Rule ids are part of the public interface. Renaming one, changing its severity,
or moving a rule into or out of the waivable set is a breaking change and is
recorded here.

## [Unreleased]

## [0.1.0] - 2026-09-29

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
- Ten enforced limits, each reported by name when reached. `maxFindings` bounds
  the run and not only the printed array: findings past it are discarded as they
  are raised and counted into `too-many-findings`, so the memory a run needs is
  bounded by the limit rather than by what the documents could raise.
- A cap of 5,000,000 on `maxRoutes` multiplied by `maxRequirements`. Those two
  limits each bound one dimension; the size of a report is their product,
  because every route row lists the required fields that route was missing. At
  the published caps that product is forty million entries and `JSON.stringify`
  refuses the report. A pair above the cap is refused in `validateLimits`,
  before any file is opened, with an empty stdout and exit 2.
- Examples that exit 0, 1 and 2.

### Changed

- `hsts-directive-duplicate` is now an `error`, it is no longer waivable, and it
  leaves the field undecided so the run is `incomplete` and exits 2. It was a
  `warning`, the first occurrence of the repeated directive was credited toward
  the requirement, and a route sending
  `Strict-Transport-Security: max-age=31536000; max-age=0` therefore reported
  `pass` with exit 0. RFC 6797 section 6.1 allows each directive once and tells a
  UA to ignore any STS field that breaks that syntax, so a conforming browser has
  no HSTS policy on that route while a lenient one has a long one; nothing in a
  capture says which browser is reading it, so there is no verdict to give.
- The determinism claim is qualified. Two runs over identical inputs produce
  byte-identical stdout unless `maxRuntimeMs` fires, because how many routes a
  run reaches before the budget trips depends on the machine. A run that trips it
  is `incomplete` with exit 2 every time, whatever it reached.

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
  the position, line and column and never the text at them.
  `parseFailureDetail` recognises the quoting shape *before* it looks for the
  offset, which is the part that matters: a capture whose own text reads
  `at position 1` makes V8 quote that text back, so an offset-first reading
  finds the offset inside the quoted span and slices the file's own text out as
  if it were V8's prose. A closing guard then discards any detail still holding
  a double quote, which is what makes the function safe against wordings this
  build has never seen. `test/parse-failure-redaction.test.mjs` drives the
  published placeholder through the real binary and asserts it absent from
  stdout, from stderr and from every prefix down to eight characters, and covers
  the `at position 1` document, a quoted span straddling a line break, and an
  unseen wording that quotes its snippet before its offset.
