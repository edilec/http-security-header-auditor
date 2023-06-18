# http-security-header-auditor

Evaluate captured HTTP response header fields against a declared policy and its
route exceptions, and explain what is missing and what contradicts itself —
entirely offline.

- **Repository:** [edilec/http-security-header-auditor](https://github.com/edilec/http-security-header-auditor)
- **Area:** Security & Privacy
- **License:** MIT
- **Dependencies:** none, at runtime or in development. Node 22 or later.

## What it is

You already have the headers. Somebody exported them from a browser session, a
proxy log, a CI smoke test, or an integration suite. This tool reads that export
and one policy document and tells you, route by route, which required fields are
absent, which forbidden fields are present, which values are outside the set you
allow, and which `Content-Security-Policy` directives contradict one another.

It is a checker, not a scanner. It never opens a socket.

```console
$ http-security-header-auditor --root examples/clean --as-of 2026-03-01
policy policy.json: 4 required, 2 forbidden, 1 exception(s).
capture capture.json: 3 of 3 route(s) evaluated, 0 failing, 0 undecided.
18 field check(s) decided, 0 left undecided, as of 2026-03-01. status pass.
INFO    policy.json/exceptions/0 exception-applied On route "legacy-report-viewer", a waiver
        for "content-security-policy" holds until 2026-09-30 and excuses
        csp-report-only-without-enforcement, required-header-missing.
```

stdout carries the JSON report and nothing else, so it pipes straight into a
parser. The human summary above goes to stderr, and `--json` suppresses it.

## Install and run

```console
$ npx http-security-header-auditor --root ./headers --as-of 2026-03-01
$ npx http-security-header-auditor --root ./headers --as-of 2026-03-01 --json | jq '.summary'
$ npx http-security-header-auditor --help
```

`--root` holds two files: `policy.json` and `capture.json`. Rename either with
`--policy` and `--capture`; both stay relative to the root, and a path that
resolves outside it — through a symbolic link included — is refused unread.

As a library:

```js
import { auditHeaders, exitCodeFor } from 'http-security-header-auditor'

const report = await auditHeaders({ root: './headers', asOf: '2026-03-01' })
process.exitCode = exitCodeFor(report)
```

## Exit codes

| Code | Meaning |
| ---: | --- |
| `0` | the capture was audited and it satisfied the policy |
| `1` | the capture was audited and at least one error-severity rule fired |
| `2` | invalid configuration (**stdout is empty**), or evidence that could not be obtained (an `incomplete` report on stdout) |

Exit 2 has two shapes on purpose. A configuration error means the run never had
a subject, so there is nothing to report about. An unreadable input means the run
had a subject and failed to obtain evidence about it — which is what `incomplete`
exists to say, and a consumer needs the report to know *which* input was not
read. Unknown evidence is never a pass.

## The distinction this tool exists for

`Content-Security-Policy-Report-Only` enforces nothing.

A report-only policy is a diagnostic channel. The browser evaluates it, sends a
violation report, and then loads the resource anyway. A route carrying only that
field has no content security policy in force — and a reviewer skimming a capture
for the string "Content-Security-Policy" will conclude the opposite.

So this tool looks the required field up by its whole name, never parses the
report-only value, records `csp.enforced` and `csp.reportOnly` separately, and
raises `csp-report-only-without-enforcement` whenever the second is true and the
first is false — whether or not the policy required a CSP at all, because
shipping report-only alone is a rollout that was never finished. A team that
means to stay in report-only for a while says so with a route exception carrying
a reason and a date.

## Contradictions it explains

| What the policy says | What the browser does |
| --- | --- |
| `default-src 'none' https://cdn.example.invalid` | `'none'` is legal only on its own; the browser ignores it and allows the CDN. |
| `script-src 'unsafe-inline' 'nonce-…'` | CSP Level 2 and later ignore `'unsafe-inline'` when a nonce is present; an older browser honours it. The directive means two different things to two readers. |
| `img-src * https://images.example.invalid` | `*` already matches it. The list reads as an allow-list and behaves as no list at all. |
| `img-src 'self'; img-src https://…` | The browser keeps the first and ignores the second. |
| `script_src 'self'` | Not a directive name. The whole segment is discarded, so scripts are unrestricted. |

Source-list analysis runs only on directives that take a source list, so
`sandbox`, `report-uri` and `upgrade-insecure-requests` are never misread as
allow-lists. A false finding in a security report costs more than a missing one.

## Route exceptions

A waiver is the only thing here that turns a failure into a pass, so it is held
to the strictest shape in the dialect: **one** route, **one** field, a reason
somebody wrote, and a date it stops applying.

```json
{
  "route": "legacy-report-viewer",
  "header": "content-security-policy",
  "reason": "CSP rollout in progress. Accepted by platform-security on 2026-02-10.",
  "expires": "2026-09-30"
}
```

Expiry is compared against `--as-of` and against nothing else — there is no clock
in this package. Without `--as-of` no expiry can be decided, so every waiver is
withheld, the findings it would have covered are reported, and the run is
`incomplete`. That is the direction that cannot turn an unknown into a pass.

**A waiver excuses a known fact, never an unknown one.** It cannot reach a field
captured twice, a value too long to parse, a value carrying a control character,
or a policy string past the directive bound. Those are gaps in the evidence, they
keep the run `incomplete` however many waivers the policy declares, and nobody
can review a statement about something nobody read.

An expired waiver is an error. A waiver that excused nothing, or names a route
the capture does not contain, is a warning — worth cleaning up, not worth failing
a build over.

## Limits and non-goals

**What this tool cannot conclude.**

- **It cannot tell you what a route actually serves.** It reads a capture
  somebody produced. If the export was stale, partial, taken from the wrong
  environment, or written by hand, every conclusion here is about that file and
  not about any running system. A pass is a statement about one capture at one
  moment.
- **It says nothing about routes nobody captured.** There is no discovery here.
  If your capture holds three routes and your application serves three hundred,
  this tool has audited three.
- **It does not know what a browser will do with a directive it has never heard
  of.** A directive outside the known catalog is reported and not analysed. When
  a requirement declares `forbiddenSources` and such a directive is present, the
  field is left *undecided* and the run is `incomplete` rather than clean,
  because a forbidden source could be hiding inside it.
- **It parses two header values structurally and no others.**
  `Content-Security-Policy` and `Strict-Transport-Security`. Everything else is
  compared as an opaque string against values you declare. There is no
  `Permissions-Policy` grammar here, no cookie attribute analysis, no CORS
  reasoning. A parser that half understands a field and reports a verdict anyway
  is worse than none, because its verdict looks like the others.
- **It does not know whether your policy is a good one.** It checks the capture
  against what you declared. `required: []` passes nothing and says so, but a
  policy that requires one weak field will happily go green.
- **A capture with no URL in it cannot be correlated with anything.** Route ids
  are opaque names. That is deliberate — see below — and it means this tool
  cannot group routes by host, path or origin.

**What it deliberately does not do.**

- **No network, ever.** No fetch, no host resolution, **no endpoint discovery**,
  no port scan, no request of any kind. `test/no-network.test.mjs` proves it four
  ways: the binary completes a real run with every network builtin refused at
  module resolution (with a control run proving the guard fires); a live loopback
  listener whose address is planted through the policy label, the route
  description and a CSP `report-uri` records that nothing ever knocked; the
  shipped source is scanned for `fetch`, `eval`, `new URL`, child processes and
  credential reads; and the input schema is checked for having nowhere to put an
  address at all.
- **No probing, no exploitation, no bypass.** This tool does not try a header
  against a browser, construct a payload, or test whether a policy can be evaded.
  It reads two files and compares them.
- **No writes.** Read-only. It never touches the root it was pointed at, and
  there is no auto-fix.
- **No clock, no locale, no randomness.** Two runs over identical inputs produce
  byte-identical stdout. Ordering is by UTF-16 code unit — field names are
  RFC 9110 tokens, so `-` and `_` both occur, and English collation orders
  `x_audit` before `x-audit` while their code points order them the other way
  round.

**Why a route has no URL.** The capture schema has no `url`, `host`, `origin` or
`endpoint` key, and an unknown key is refused rather than ignored. That is the
structural half of "nothing is ever fetched": a tool whose input has no address
in it cannot resolve one by accident, and a future change that wanted to would
have to add the field first, in public, in a schema version bump.

## Bounds

Every limit is enforced and exceeding one produces a finding that names it —
never a silent truncation, never a pass. `docs/header-rules.md` lists all ten
with their defaults, caps and flags.

The bound that carries the weight is `maxHeaderValueLength`, because it is the
one that can actually fire. You cannot bound a regular expression with a time
check around the call: the engine does not yield. So nothing here compiles a
regular expression from input at all — the policy string and the HSTS value are
split on ASCII delimiters and walked once — and the work is linear in a length
capped *before* either parser runs. `maxRuntimeMs` is a second line, checked once
per route, which makes a route atomic: a row exists in the report only for a
route evaluated end to end, and the run compares rows against routes *after* the
loop rather than trusting the loop to have finished.

## Documentation

- `docs/header-rules.md` — the input dialect, the waiver rules, every
  contradiction this build detects, all fifty-three rules with their severities,
  the limits, and the report shape.
- `examples/clean` — exits 0, with one applied waiver.
- `examples/broken` — exits 1, across fourteen error findings.
- `examples/incomplete` — exits 2, because a field captured twice and a directive
  this build does not analyse are gaps in the evidence, not verdicts about it.

## Development

```console
$ npm run check     # lint, test, example, pack:check
```

`npm run lint` is `node --check` over every file. `npm test` is `node --test`.
There is nothing to install.

## License

MIT. See [LICENSE](./LICENSE).
