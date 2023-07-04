# Rule catalog, input dialect and limits

This document is the reference half of the tool. `README.md` says what it is
for; this says exactly what it reads, exactly what it can conclude, and exactly
where it stops.

The severity column below is the authority a reader can check against
`src/rules.mjs`, and `test/severity-table.test.mjs` asserts the two against each
other in both directions. That check is worth having and it is not the guarantee:
a table, a document and a test's expected map are three declarations, and one
edit that changes all three leaves every comparison between them satisfied.
`test/severity-exit.test.mjs` and `test/severity-word.test.mjs` pin severity by
driving real inputs through the real binary and asserting the exit code, the
error count and the printed word with literal values.

## Input dialect

Two JSON documents, both inside a declared root directory, both
`"schemaVersion": "1"`.

### `capture.json`

```json
{
  "schemaVersion": "1",
  "label": "staging capture, exported by hand",
  "routes": [
    {
      "id": "app-root",
      "description": "Document response for the signed-in shell.",
      "headers": [
        { "name": "Content-Security-Policy", "value": "default-src 'self'" }
      ]
    }
  ]
}
```

| Key | Required | Meaning |
| --- | --- | --- |
| `schemaVersion` | yes | `"1"`. Any other value is unsupported, not ignored. |
| `label` | no | Free text, at most 300 characters. Metadata only. |
| `routes` | yes | Array of captured responses. `[]` is legal. |
| `routes[].id` | yes | 1–120 characters from `[A-Za-z0-9._:+/-]`, starting with a letter or digit. Unique within the document. |
| `routes[].description` | no | Free text, at most 300 characters. |
| `routes[].headers` | yes | Array of `{name, value}`. `[]` is legal. |
| `headers[].name` | yes | An RFC 9110 token, 1–80 characters. Compared case-insensitively. |
| `headers[].value` | yes | A string. Refused if it exceeds `maxHeaderValueLength` or carries a control, separator or bidi character. |

**A route has no URL, and there is nowhere to put one.** The identifier is an
opaque name somebody chose when they exported the capture. That is deliberate:
it is the structural half of "nothing is ever fetched". A tool whose input
schema has no address in it cannot resolve one by accident.

Repeating a field name inside one route is representable, and it is reported:
see `header-duplicated`.

### `policy.json`

```json
{
  "schemaVersion": "1",
  "required": [
    {
      "header": "content-security-policy",
      "requiredDirectives": ["default-src", "frame-ancestors"],
      "forbiddenSources": ["'unsafe-inline'", "*"]
    },
    { "header": "strict-transport-security", "minMaxAge": 31536000, "requireIncludeSubDomains": true },
    { "header": "x-content-type-options", "allowedValues": ["nosniff"] }
  ],
  "forbidden": [{ "header": "x-powered-by" }],
  "exceptions": [
    {
      "route": "legacy-report-viewer",
      "header": "content-security-policy",
      "reason": "CSP rollout in progress. Accepted by platform-security on 2026-02-10.",
      "expires": "2026-09-30"
    }
  ]
}
```

| Key | Applies to | Meaning |
| --- | --- | --- |
| `required[].header` | any field | The field must be present on every captured route. |
| `required[].description` | any field | Free text, at most 300 characters. |
| `required[].allowedValues` | any field | 1–32 strings. The captured value is trimmed and ASCII-lowercased before comparison, as is each allowed value. |
| `required[].requiredDirectives` | `content-security-policy` only | 1–40 directive names from `[A-Za-z0-9-]`, each of which must appear in the policy string. |
| `required[].forbiddenSources` | `content-security-policy` only | 1–40 source expressions, none of which may appear in any source-list directive. |
| `required[].minMaxAge` | `strict-transport-security` only | Integer seconds, 0–315360000. |
| `required[].requireIncludeSubDomains` | `strict-transport-security` only | `true` requires the token. `false` requires nothing. |
| `required[].requirePreload` | `strict-transport-security` only | `true` requires the token. `false` requires nothing. |
| `forbidden[].header` | any field | The field must be absent from every captured route. |
| `exceptions[].route` | — | Exactly one route id. Never a pattern. |
| `exceptions[].header` | — | Exactly one field name. Never a pattern. |
| `exceptions[].reason` | — | Non-empty, at most 300 characters. |
| `exceptions[].expires` | — | A calendar date written `YYYY-MM-DD`. |

An option declared on a field this build does not read it on is **refused**, not
ignored — `minMaxAge` on an `X-Frame-Options` requirement is a `policy-invalid`
finding. Silently dropping it would leave a policy author believing a bound is
enforced that nothing enforces.

A field that appears in both `required` and `forbidden` is a
`policy-contradiction`: no response can satisfy both, so **neither entry is
evaluated against any route**.

## Route exceptions

An exception is the only construct that turns a failure into a pass, so it is
held to the strictest shape in the dialect.

- It names **one** route and **one** field. A pattern is
  `pattern-unsupported` and the exception is refused.
- It carries a **reason**. A waiver nobody can review is a waiver nobody agreed
  to.
- It carries an **expiry**. A waiver with no end date is a policy change wearing
  a waiver's clothes.
- Expiry is compared against `--as-of`, and against nothing else. A waiver whose
  `expires` is on or after that date holds; one strictly before it has expired.
  **Without `--as-of` no expiry can be decided**: every waiver is withheld, the
  findings it would have covered are reported, and the run is `incomplete`.

An exception waives the rules marked waivable in the catalog below and no
others. The rules it cannot reach are the ones that say the evidence was not
obtained — a field captured twice, a value too long to parse, a value carrying a
control character, a policy string past the directive bound. Those keep the run
`incomplete` however many waivers the policy declares, because a waiver is a
statement about a known fact and nobody can review a statement about something
nobody read.

## What `Content-Security-Policy-Report-Only` means here

Nothing. That is the point.

A report-only policy is a diagnostic channel: the browser evaluates the policy,
sends a violation report to the endpoint the policy names, and then loads the
resource anyway. A route carrying `Content-Security-Policy-Report-Only` and no
`Content-Security-Policy` has no content security policy in force.

This tool therefore:

- looks the required field up by its **whole** name, so the report-only field can
  never satisfy a requirement for the enforcing one;
- never parses the report-only value, so its directives are never credited to the
  route and `routes[].csp.directives` stays empty;
- records `routes[].csp.reportOnly` separately from `routes[].csp.enforced`;
- raises `csp-report-only-without-enforcement` whenever the first is true and the
  second is false, **whether or not the policy required a CSP at all**, because
  shipping report-only alone is a rollout that was never finished.

A team that means to stay in report-only for a while says so with a route
exception carrying a reason and a date. That is what route exceptions are for.

## Contradictions this build detects

All of these are statements about what the CSP specification says a browser will
do, not guesses about what an author intended.

| Contradiction | Rule | What a browser does |
| --- | --- | --- |
| `'none'` listed beside other sources | `csp-none-with-sources` | The grammar permits `'none'` only on its own; the browser ignores it and honours the rest. |
| `'unsafe-inline'` beside a nonce or a hash | `csp-unsafe-inline-with-nonce` | CSP Level 2 and later ignore `'unsafe-inline'` when a nonce or hash is present; an older browser honours it. The directive means two different things to two readers. |
| `*` beside named hosts | `csp-wildcard-shadows-sources` | `*` already matches all of them. The list reads as an allow-list and behaves as no list at all. |
| The same directive declared twice | `csp-directive-duplicate` | The browser keeps the first and ignores the second. What runs is not what the policy says. |
| The same source listed twice | `csp-source-duplicate` | Nothing. The repeat allows nothing extra. |
| A segment whose first token is not a directive name | `csp-directive-malformed` | The browser discards the whole segment, so whatever it restricted is unrestricted. |

Source-list analysis runs **only** on directives that take a source list.
`sandbox` takes sandboxing flags, `report-uri` takes URIs,
`require-trusted-types-for` takes `'script'`, and `upgrade-insecure-requests`
takes nothing at all; running the rules above over any of them would invent
contradictions that are not there, and a false finding in a security report
costs more than a missing one.

## Rule catalog

`waivable` says whether a route exception can excuse the rule.

| Rule id | Severity | Waivable |
| --- | --- | --- |
| `csp-analysis-incomplete` | error | no |
| `csp-directive-duplicate` | error | yes |
| `csp-directive-malformed` | error | yes |
| `csp-directive-missing` | error | yes |
| `csp-directive-unknown` | warning | yes |
| `csp-none-with-sources` | error | yes |
| `csp-report-only-without-enforcement` | error | yes |
| `csp-source-duplicate` | warning | yes |
| `csp-source-forbidden` | error | yes |
| `csp-unparseable` | error | no |
| `csp-unsafe-inline-with-nonce` | error | yes |
| `csp-wildcard-shadows-sources` | warning | yes |
| `document-invalid` | error | no |
| `exception-applied` | info | no |
| `exception-expired` | error | no |
| `exception-expiry-missing` | error | no |
| `exception-expiry-undecidable` | error | no |
| `exception-reason-missing` | error | no |
| `exception-route-unknown` | warning | no |
| `exception-unused` | warning | no |
| `forbidden-header-present` | error | yes |
| `header-duplicated` | error | no |
| `header-invalid` | error | no |
| `header-value-control-character` | error | no |
| `header-value-too-long` | error | no |
| `header-value-unexpected` | error | yes |
| `hsts-directive-duplicate` | warning | yes |
| `hsts-directive-unknown` | warning | yes |
| `hsts-include-subdomains-missing` | error | yes |
| `hsts-max-age-malformed` | error | yes |
| `hsts-max-age-missing` | error | yes |
| `hsts-max-age-too-short` | error | yes |
| `hsts-preload-missing` | error | yes |
| `identifier-invalid` | error | no |
| `input-not-json` | error | no |
| `input-not-utf8` | error | no |
| `input-too-large` | error | no |
| `input-unreadable` | error | no |
| `no-checks-performed` | error | no |
| `path-escapes-root` | error | no |
| `pattern-unsupported` | error | no |
| `policy-contradiction` | error | no |
| `policy-invalid` | error | no |
| `required-header-missing` | error | yes |
| `route-duplicate` | error | no |
| `route-invalid` | error | no |
| `schema-version-unsupported` | error | no |
| `time-budget-exceeded` | error | no |
| `too-many-exceptions` | error | no |
| `too-many-findings` | error | no |
| `too-many-headers` | error | no |
| `too-many-requirements` | error | no |
| `too-many-routes` | error | no |

### Which rules make a run `incomplete`

`incomplete` means evidence was missing, refused or unsupported. It is never
interchangeable with `pass`, and it exits 2.

- Anything that stopped a document being read or compiled: `input-unreadable`,
  `input-not-utf8`, `input-not-json`, `input-too-large`, `path-escapes-root`,
  `document-invalid`, `schema-version-unsupported`, every `too-many-*`.
- Anything that stopped an entry being compiled: `route-invalid`,
  `route-duplicate`, `header-invalid`, `identifier-invalid`,
  `pattern-unsupported`, `policy-invalid`, `policy-contradiction`,
  `exception-reason-missing`, `exception-expiry-missing`.
- Anything that left a field undecided: `header-duplicated`,
  `header-value-too-long`, `header-value-control-character`, `csp-unparseable`,
  `csp-analysis-incomplete`.
- `exception-expiry-undecidable`, because no expiry could be compared.
- `time-budget-exceeded`, and more precisely the count of route rows that exist
  compared against the number of routes that compiled.
- `no-checks-performed`, which refuses the vacuous pass.

`input-not-json` reports the position, line and column of the parse failure and
never the text at it. V8 quotes the input back in its own parse message, so a
capture short enough to be nothing but a credential would otherwise be
reproduced in full by its own error.

## Limits

Every limit is enforced, and exceeding one produces a finding that names it.
Exceeding a limit is never a silent truncation and never a pass.

| Limit | Default | Cap | Flag |
| --- | ---: | ---: | --- |
| `maxCspDirectives` | 50 | 500 | `--max-csp-directives` |
| `maxCspSources` | 100 | 2000 | `--max-csp-sources` |
| `maxExceptions` | 200 | 5000 | `--max-exceptions` |
| `maxFileBytes` | 5242880 | 67108864 | `--max-file-bytes` |
| `maxFindings` | 1000 | 20000 | `--max-findings` |
| `maxHeaderValueLength` | 8192 | 131072 | `--max-header-value-length` |
| `maxHeadersPerRoute` | 100 | 2000 | `--max-headers-per-route` |
| `maxRequirements` | 100 | 2000 | `--max-requirements` |
| `maxRoutes` | 500 | 20000 | `--max-routes` |
| `maxRuntimeMs` | 10000 | 600000 | `--max-runtime-ms` |

An unknown limit name is a configuration error, not a key to ignore: a
one-character typo must not turn a real failure into a green run.

`maxFindings` bounds the run, not only the printed array. Findings past the limit
are discarded as they are raised and counted, and the count becomes the
`too-many-findings` finding; nothing accumulates a report that would then be
sliced down to size. The findings a truncated report keeps are therefore the
first ones raised — emission order is fixed by the documents, so this is
deterministic — and they are sorted for printing like any other report.

### The one bound that is a product

`maxRoutes` and `maxRequirements` each bound one dimension, and each is enforced
exactly as the table says. The size of a report is neither of them: every route
row lists the required fields that route was missing, so the entries are
`maxRoutes` multiplied by `maxRequirements`. At the caps above that product is
forty million, and a run at the caps built a report `JSON.stringify` refused —
`RangeError: Invalid string length`, an empty stdout, and an exit code claiming
the capture was audited and failed. It was not audited and nothing failed.

So the product is capped at **5,000,000 field checks**, and it is checked where
the other limits are validated, before any file is opened. A configuration this
build cannot carry to a report is refused with an empty stdout and exit 2, the
same way an unknown limit key and an out-of-range value already are: a
configuration is not a subject, so refusing one claims nothing about anything.
The default limits ask for 50,000. The number is measured — at five million
checks the largest report this shape produces is 137 MB of stdout and 927 MB of
resident memory in 6.3 s.

### Why `maxHeaderValueLength` is the bound that matters

You cannot bound a regular expression with a time check around the call, because
the engine does not yield. Two tools in this catalog ran for 6.8 and 184 seconds
under declared 100 ms budgets for exactly that reason.

So this package does not rely on one. Nothing here compiles a regular expression
from input — the policy string and the HSTS value are split on ASCII delimiters
and walked once — and the work is linear in a length this limit caps *before*
either parser runs. `maxRuntimeMs` exists as a second line, checked once per
route, which makes a route atomic: a row exists in the report only for a route
that was evaluated from end to end, and the run compares rows against routes
after the loop rather than trusting the loop to have finished.

## Determinism

- Findings sort by `location.file`, then `location.pointer`, then `ruleId`, then
  `message`.
- Route rows sort by route id. Every array inside a row sorts by code unit.
- Ordering is by UTF-16 code unit everywhere. Field names are RFC 9110 tokens, so
  `-` and `_` both occur in real ones, and English collation orders `x_audit`
  before `x-audit` while their code points order them the other way round.
- No locale, no random source, no filesystem enumeration order. The only date
  the tool reads is the one `--as-of` carries.
- The one clock is the monotonic source `maxRuntimeMs` is measured against, and
  it is the one thing that breaks byte-identity: a run that trips the budget
  reaches however many routes the machine let it reach. Two runs over identical
  inputs are byte-identical unless the budget fires. When it does, the report is
  `incomplete` with exit 2 every time regardless of where it stopped — the
  amount of evidence varies, the verdict direction does not.

## Report shape

```json
{
  "schemaVersion": "1",
  "tool": "http-security-header-auditor",
  "status": "pass",
  "asOf": "2026-03-01",
  "summary": {
    "checked": 18, "errors": 0, "warnings": 0,
    "routes": 3, "evaluated": 3, "unevaluated": 0, "undecided": 0,
    "requirements": 4, "forbidden": 2,
    "exceptionsDeclared": 1, "exceptionsApplied": 1, "exceptionsExpired": 0,
    "routesFailing": 0, "routesUndecided": 0
  },
  "routes": [
    {
      "id": "legacy-report-viewer",
      "verdict": "waived",
      "headers": ["content-security-policy-report-only", "referrer-policy"],
      "missing": ["content-security-policy"],
      "waived": ["content-security-policy"],
      "undecided": [],
      "csp": { "enforced": false, "reportOnly": true, "analysed": false, "directives": [] }
    }
  ],
  "findings": []
}
```

`checked` counts decided pairs: one per route and required field, plus one per
route and forbidden field. A pair left undecided is counted in `undecided`
instead, never in `checked`.

`verdict` is one of `pass`, `waived`, `fail`, `undecided`, in increasing
precedence. A route that was not evaluated has **no row at all** — an absent row
is not a quiet pass, and `summary.unevaluated` says how many are missing.
