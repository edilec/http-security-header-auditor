#!/usr/bin/env node

import process from 'node:process'

import {
  DEFAULT_CAPTURE_NAME,
  DEFAULT_POLICY_NAME,
  auditHeaders,
  excerpt,
  exitCodeFor,
  formatReport,
  serializeReport,
} from '../src/index.mjs'

const VERSION = '0.1.0'

const HELP = `http-security-header-auditor

Evaluate captured HTTP response header fields against a declared policy and its
route exceptions, and explain what is missing and what contradicts itself.

Nothing is fetched. No host is resolved, no endpoint is discovered, no port is
touched: the capture is a file somebody exported, and it is the only evidence
there is. A route in that file is an opaque name, not an address, so there is
nowhere for a URL to live in the input at all.

Usage:
  http-security-header-auditor --root DIR [--policy FILE] [--capture FILE]
                               [--as-of YYYY-MM-DD] [--json]
                               [--max-routes N] [--max-headers-per-route N]
                               [--max-header-value-length N]
                               [--max-requirements N] [--max-exceptions N]
                               [--max-csp-directives N] [--max-csp-sources N]
                               [--max-file-bytes N] [--max-runtime-ms N]
                               [--max-findings N]

Options:
  --root DIR                    Directory holding both documents (required)
  --policy FILE                 Policy document, relative to --root
                                (default ${DEFAULT_POLICY_NAME})
  --capture FILE                Captured responses, relative to --root
                                (default ${DEFAULT_CAPTURE_NAME})
  --as-of YYYY-MM-DD            Date that exception expiries are compared
                                against. Without it no expiry can be decided,
                                every waiver is withheld, and the run is
                                incomplete.
  --json                        Suppress the human summary on stderr
  --max-routes N                Maximum captured routes (default 500)
  --max-headers-per-route N     Maximum fields per route (default 100)
  --max-header-value-length N   Maximum characters in one value (default 8192)
  --max-requirements N          Maximum required plus forbidden fields (default 100)
  --max-exceptions N            Maximum route exceptions (default 200)
  --max-csp-directives N        Maximum segments in one policy string (default 50)
  --max-csp-sources N           Maximum sources in one directive (default 100)
  --max-file-bytes N            Maximum bytes per document (default 5242880)
  --max-runtime-ms N            Time budget for the audit (default 10000)
  --max-findings N              Maximum findings in one report (default 1000)
  -h, --help                    Show this help
  -v, --version                 Show the version

Every option that carries a value may be given only once: a repeated flag is a
configuration error, not a silent last-wins.

Output:
  stdout  the JSON report only, so it can be piped straight into a parser
  stderr  the human summary and diagnostics

What a pass means:
  Every field the policy requires was present on every captured route, every
  field it forbids was absent, every value it constrains matched, and no policy
  string contradicted itself -- except where a route exception with a reason and
  an unexpired date said otherwise. It is a statement about one capture, made at
  one moment, about the fields that capture recorded. It says nothing about a
  route nobody captured, nothing about what a browser will do with a directive
  this build does not know, and nothing about whether the origin serving those
  fields is otherwise sound.

  Content-Security-Policy-Report-Only never counts as a policy. A route carrying
  only that field is reported as having no content security policy in force,
  because that is what it has.

Exit codes:
  0  the capture was audited and it satisfied the policy
  1  the capture was audited and at least one error-severity rule fired
  2  invalid configuration (no report on stdout), or evidence that could not be
     obtained (an "incomplete" report on stdout, never a "pass")
`

const LIMIT_FLAGS = new Map([
  ['--max-csp-directives', 'maxCspDirectives'],
  ['--max-csp-sources', 'maxCspSources'],
  ['--max-exceptions', 'maxExceptions'],
  ['--max-file-bytes', 'maxFileBytes'],
  ['--max-findings', 'maxFindings'],
  ['--max-header-value-length', 'maxHeaderValueLength'],
  ['--max-headers-per-route', 'maxHeadersPerRoute'],
  ['--max-requirements', 'maxRequirements'],
  ['--max-routes', 'maxRoutes'],
  ['--max-runtime-ms', 'maxRuntimeMs'],
])

const VALUE_FLAGS = new Map([
  ['--as-of', 'asOf'],
  ['--capture', 'capture'],
  ['--policy', 'policy'],
  ['--root', 'root'],
])

function parseArguments(argv) {
  if (argv.includes('-h') || argv.includes('--help')) return { help: true }
  if (argv.includes('-v') || argv.includes('--version')) return { version: true }

  const options = { root: null, policy: null, capture: null, asOf: null, json: false, limits: {} }
  const given = new Set()

  /**
   * A flag that carries a value is accepted once.
   *
   * Letting it repeat discards the earlier value with no diagnostic, so
   * `--capture a.json --capture b.json` audits a file nobody named and
   * `--as-of 2020-01-01 --as-of 2030-01-01` silently revives every expired
   * waiver. That is the same defect as an ignored typo, which this tool also
   * refuses.
   */
  const once = (name) => {
    if (given.has(name)) throw new Error(`${name} was given more than once`)
    given.add(name)
  }

  for (let index = 0; index < argv.length; index += 1) {
    const argument = argv[index]
    const takeValue = (name) => {
      const value = argv[index + 1]
      if (value === undefined || value.startsWith('-')) throw new Error(`${name} requires a value`)
      index += 1
      return value
    }

    if (argument === '--json') options.json = true
    else if (VALUE_FLAGS.has(argument)) {
      once(argument)
      options[VALUE_FLAGS.get(argument)] = takeValue(argument)
    } else if (LIMIT_FLAGS.has(argument)) {
      once(argument)
      const raw = takeValue(argument)
      if (!/^\d+$/.test(raw) || Number(raw) < 1) throw new Error(`${argument} requires a positive integer`)
      options.limits[LIMIT_FLAGS.get(argument)] = Number(raw)
    // argv is the one untrusted string that reaches a stream without passing
    // through a finding, so it is flattened exactly as a finding would be.
    } else throw new Error(`Unknown option "${excerpt(argument, 60)}"`)
  }

  if (options.root === null) throw new Error('--root is required')
  return options
}

async function main(argv) {
  let options
  try {
    options = parseArguments(argv)
  } catch (error) {
    process.stderr.write(`${error.message}\n\n${HELP}`)
    return 2
  }
  if (options.help) {
    process.stdout.write(HELP)
    return 0
  }
  if (options.version) {
    process.stdout.write(`${VERSION}\n`)
    return 0
  }

  let report
  try {
    report = await auditHeaders({
      root: options.root,
      limits: options.limits,
      ...(options.policy === null ? {} : { policy: options.policy }),
      ...(options.capture === null ? {} : { capture: options.capture }),
      ...(options.asOf === null ? {} : { asOf: options.asOf }),
    })
  } catch (error) {
    // A configuration error never had a subject, so stdout stays empty and the
    // consumer that pipes stdout gets nothing rather than a fabricated report.
    process.stderr.write(`${excerpt(error.message, 400)}\n`)
    return 2
  }

  process.stdout.write(`${serializeReport(report)}\n`)
  if (!options.json) {
    process.stderr.write(formatReport(report, {
      policy: options.policy ?? undefined,
      capture: options.capture ?? undefined,
    }))
  }
  if (report.status === 'incomplete') {
    process.stderr.write(
      `incomplete: ${report.summary.evaluated} of ${report.summary.routes} route(s) were evaluated and ${report.summary.undecided} field check(s) were left undecided; this run is not a pass.\n`,
    )
  }
  return exitCodeFor(report)
}

process.exitCode = await main(process.argv.slice(2))
