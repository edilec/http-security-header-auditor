/**
 * Severity, pinned by what the tool actually prints, for every rule in the
 * catalog.
 *
 * This file deliberately shares nothing with the rest of the suite. It imports
 * no severity table, reads no documented catalog, and takes no expectation from
 * a map, a fixture module or a loop variable: every rule id, every count and
 * every printed line is written out inline, at the place it is asserted.
 *
 * That is the whole point. A frozen table, a markdown catalog and a test's
 * expected-value map are three declarations, and one edit that changes all three
 * leaves every assertion that compares them satisfied -- including an assertion
 * made inside a loop over that same map. Nothing below can be satisfied by
 * editing a declaration. `assert.equal(report.summary.errors, 1)` is false the
 * moment a rule stops being an error, and `stderr.includes('ERROR   ...')` is
 * false the moment it stops being printed as one.
 *
 * Most of the error rules also mark the run incomplete, so they exit 2 whether
 * their severity says `error` or `warning`; for those the exit code is not the
 * discriminator and the error count and the printed word are.
 * `test/severity-exit.test.mjs` covers the twenty-four rules that complete the
 * run, where the exit code itself flips.
 *
 * The builders below are inputs. They carry no severity, no rule id and no
 * count.
 */

import assert from 'node:assert/strict'
import { execFile } from 'node:child_process'
import { mkdtemp, rm, symlink, writeFile } from 'node:fs/promises'
import { tmpdir } from 'node:os'
import { dirname, join } from 'node:path'
import test from 'node:test'
import { fileURLToPath } from 'node:url'
import { promisify } from 'node:util'

import { auditHeaders, exitCodeFor, formatReport } from '../src/index.mjs'

const execFileAsync = promisify(execFile)
const CLI = join(dirname(fileURLToPath(import.meta.url)), '../bin/http-security-header-auditor.mjs')

/** Build a root, run the real binary over it with the human summary on, tear the root down. */
async function audit(files, extraArgs = [], plant) {
  const root = await mkdtemp(join(tmpdir(), 'http-security-header-auditor-word-'))
  try {
    for (const [name, content] of Object.entries(files)) {
      const bytes = typeof content === 'string' || content instanceof Uint8Array ? content : JSON.stringify(content)
      await writeFile(join(root, name), bytes)
    }
    if (plant !== undefined) await plant(root)
    try {
      const { stdout, stderr } = await execFileAsync(process.execPath, [CLI, '--root', root, ...extraArgs], { maxBuffer: 64 * 1024 * 1024 })
      return { code: 0, report: JSON.parse(stdout), stderr }
    } catch (error) {
      return { code: error.code, report: JSON.parse(error.stdout), stderr: error.stderr ?? '' }
    }
  } finally {
    await rm(root, { recursive: true, force: true })
  }
}

const XCTO = { name: 'X-Content-Type-Options', value: 'nosniff' }
const OK_ROUTE = { id: 'ok', headers: [XCTO] }
const REQUIRE_XCTO = { header: 'x-content-type-options' }
const REQUIRE_CSP = { header: 'content-security-policy' }
const REQUIRE_HSTS = { header: 'strict-transport-security' }

const policy = (parts) => ({ schemaVersion: '1', ...parts })
const capture = (routes) => ({ schemaVersion: '1', routes })
const cspRoute = (id, value) => ({ id, headers: [{ name: 'Content-Security-Policy', value }] })
const hstsRoute = (id, value) => ({ id, headers: [{ name: 'Strict-Transport-Security', value }] })

test('csp-analysis-incomplete prints ERROR and counts one error', async () => {
  const { code, report, stderr } = await audit({
    'policy.json': policy({ required: [{ header: 'content-security-policy', forbiddenSources: ["'unsafe-inline'"] }, REQUIRE_XCTO] }),
    'capture.json': capture([{ id: 'future', headers: [{ name: 'Content-Security-Policy', value: "future-directive 'self'" }, XCTO] }]),
  })

  assert.equal(report.summary.errors, 1)
  assert.equal(report.summary.warnings, 1)
  assert.equal(report.status, 'incomplete')
  assert.equal(code, 2)
  assert.equal(stderr.includes('ERROR   capture.json/routes/0/headers/0/value csp-analysis-incomplete'), true)
})

test('csp-directive-duplicate prints ERROR and counts one error', async () => {
  const { code, report, stderr } = await audit({
    'policy.json': policy({ required: [REQUIRE_CSP] }),
    'capture.json': capture([cspRoute('twice', "img-src 'self'; img-src 'self'")]),
  })

  assert.equal(report.summary.errors, 1)
  assert.equal(report.status, 'fail')
  assert.equal(code, 1)
  assert.equal(stderr.includes('ERROR   capture.json/routes/0/headers/0/value csp-directive-duplicate'), true)
})

test('csp-directive-malformed prints ERROR and counts one error', async () => {
  const { code, report, stderr } = await audit({
    'policy.json': policy({ required: [REQUIRE_CSP] }),
    'capture.json': capture([cspRoute('typo', "default-src 'self'; script_src 'self'")]),
  })

  assert.equal(report.summary.errors, 1)
  assert.equal(report.status, 'fail')
  assert.equal(code, 1)
  assert.equal(stderr.includes('ERROR   capture.json/routes/0/headers/0/value csp-directive-malformed'), true)
})

test('csp-directive-missing prints ERROR and counts one error', async () => {
  const { code, report, stderr } = await audit({
    'policy.json': policy({ required: [{ header: 'content-security-policy', requiredDirectives: ['frame-ancestors'] }] }),
    'capture.json': capture([cspRoute('partial', "default-src 'self'")]),
  })

  assert.equal(report.summary.errors, 1)
  assert.equal(report.status, 'fail')
  assert.equal(code, 1)
  assert.equal(stderr.includes('ERROR   capture.json/routes/0/headers/0/value csp-directive-missing'), true)
})

test('csp-directive-unknown prints WARNING and counts no error', async () => {
  const { code, report, stderr } = await audit({
    'policy.json': policy({ required: [REQUIRE_CSP] }),
    'capture.json': capture([cspRoute('future', "future-directive 'self'")]),
  })

  assert.equal(report.summary.errors, 0)
  assert.equal(report.summary.warnings, 1)
  assert.equal(report.status, 'pass')
  assert.equal(code, 0)
  assert.equal(stderr.includes('WARNING capture.json/routes/0/headers/0/value csp-directive-unknown'), true)
})

test('csp-none-with-sources prints ERROR and counts one error', async () => {
  const { code, report, stderr } = await audit({
    'policy.json': policy({ required: [REQUIRE_CSP] }),
    'capture.json': capture([cspRoute('both', "default-src 'none' https://a.example.invalid")]),
  })

  assert.equal(report.summary.errors, 1)
  assert.equal(report.status, 'fail')
  assert.equal(code, 1)
  assert.equal(stderr.includes('ERROR   capture.json/routes/0/headers/0/value csp-none-with-sources'), true)
})

test('csp-report-only-without-enforcement prints ERROR and counts one error', async () => {
  const { code, report, stderr } = await audit({
    'policy.json': policy({ required: [REQUIRE_XCTO] }),
    'capture.json': capture([{ id: 'rollout', headers: [{ name: 'Content-Security-Policy-Report-Only', value: "default-src 'self'" }, XCTO] }]),
  })

  assert.equal(report.summary.errors, 1)
  assert.equal(report.status, 'fail')
  assert.equal(code, 1)
  assert.equal(stderr.includes('ERROR   capture.json/routes/0/headers/0 csp-report-only-without-enforcement'), true)
})

test('csp-source-duplicate prints WARNING and counts no error', async () => {
  const { code, report, stderr } = await audit({
    'policy.json': policy({ required: [REQUIRE_CSP] }),
    'capture.json': capture([cspRoute('repeated', "script-src 'self' 'self'")]),
  })

  assert.equal(report.summary.errors, 0)
  assert.equal(report.summary.warnings, 1)
  assert.equal(report.status, 'pass')
  assert.equal(code, 0)
  assert.equal(stderr.includes('WARNING capture.json/routes/0/headers/0/value csp-source-duplicate'), true)
})

test('csp-source-forbidden prints ERROR and counts one error', async () => {
  const { code, report, stderr } = await audit({
    'policy.json': policy({ required: [{ header: 'content-security-policy', forbiddenSources: ["'unsafe-eval'"] }] }),
    'capture.json': capture([cspRoute('loose', "script-src 'unsafe-eval'")]),
  })

  assert.equal(report.summary.errors, 1)
  assert.equal(report.status, 'fail')
  assert.equal(code, 1)
  assert.equal(stderr.includes('ERROR   capture.json/routes/0/headers/0/value csp-source-forbidden'), true)
})

test('csp-unparseable prints ERROR and counts one error', async () => {
  const { code, report, stderr } = await audit({
    'policy.json': policy({ required: [REQUIRE_CSP, REQUIRE_XCTO] }),
    'capture.json': capture([{ id: 'wide', headers: [{ name: 'Content-Security-Policy', value: "default-src 'self'; img-src 'self'" }, XCTO] }]),
  }, ['--max-csp-directives', '1'])

  assert.equal(report.summary.errors, 1)
  assert.equal(report.status, 'incomplete')
  assert.equal(code, 2)
  assert.equal(stderr.includes('ERROR   capture.json/routes/0/headers/0/value csp-unparseable'), true)
})

test('csp-unsafe-inline-with-nonce prints ERROR and counts one error', async () => {
  const { code, report, stderr } = await audit({
    'policy.json': policy({ required: [REQUIRE_CSP] }),
    'capture.json': capture([cspRoute('mixed', "script-src 'unsafe-inline' 'nonce-abc'")]),
  })

  assert.equal(report.summary.errors, 1)
  assert.equal(report.status, 'fail')
  assert.equal(code, 1)
  assert.equal(stderr.includes('ERROR   capture.json/routes/0/headers/0/value csp-unsafe-inline-with-nonce'), true)
})

test('csp-wildcard-shadows-sources prints WARNING and counts no error', async () => {
  const { code, report, stderr } = await audit({
    'policy.json': policy({ required: [REQUIRE_CSP] }),
    'capture.json': capture([cspRoute('wide', 'img-src * https://a.example.invalid')]),
  })

  assert.equal(report.summary.errors, 0)
  assert.equal(report.summary.warnings, 1)
  assert.equal(report.status, 'pass')
  assert.equal(code, 0)
  assert.equal(stderr.includes('WARNING capture.json/routes/0/headers/0/value csp-wildcard-shadows-sources'), true)
})

test('document-invalid prints ERROR and counts one error', async () => {
  const { code, report, stderr } = await audit({
    'policy.json': policy({ requiredd: [] }),
    'capture.json': capture([OK_ROUTE]),
  })

  assert.equal(report.summary.errors, 1)
  assert.equal(report.status, 'incomplete')
  assert.equal(code, 2)
  assert.equal(stderr.includes('ERROR   policy.json document-invalid'), true)
})

test('exception-applied prints INFO and counts neither an error nor a warning', async () => {
  const { code, report, stderr } = await audit({
    'policy.json': policy({
      required: [REQUIRE_XCTO],
      exceptions: [{ route: 'bare', header: 'x-content-type-options', reason: 'Scheduled.', expires: '2099-12-31' }],
    }),
    'capture.json': capture([{ id: 'bare', headers: [] }]),
  }, ['--as-of', '2026-03-01'])

  assert.equal(report.summary.errors, 0)
  assert.equal(report.summary.warnings, 0)
  assert.equal(report.status, 'pass')
  assert.equal(code, 0)
  assert.equal(stderr.includes('INFO    policy.json/exceptions/0 exception-applied'), true)
})

test('exception-expired prints ERROR and counts two errors with the finding it uncovered', async () => {
  const { code, report, stderr } = await audit({
    'policy.json': policy({
      required: [REQUIRE_XCTO],
      exceptions: [{ route: 'bare', header: 'x-content-type-options', reason: 'Overdue.', expires: '2025-01-31' }],
    }),
    'capture.json': capture([{ id: 'bare', headers: [] }]),
  }, ['--as-of', '2026-03-01'])

  assert.equal(report.summary.errors, 2)
  assert.equal(report.status, 'fail')
  assert.equal(code, 1)
  assert.equal(stderr.includes('ERROR   policy.json/exceptions/0/expires exception-expired'), true)
})

test('exception-expiry-missing prints ERROR and counts one error', async () => {
  const { code, report, stderr } = await audit({
    'policy.json': policy({
      required: [REQUIRE_XCTO],
      exceptions: [{ route: 'ok', header: 'x-content-type-options', reason: 'No end date.' }],
    }),
    'capture.json': capture([OK_ROUTE]),
  }, ['--as-of', '2026-03-01'])

  assert.equal(report.summary.errors, 1)
  assert.equal(report.status, 'incomplete')
  assert.equal(code, 2)
  assert.equal(stderr.includes('ERROR   policy.json/exceptions/0/expires exception-expiry-missing'), true)
})

test('exception-expiry-undecidable prints ERROR and counts two errors', async () => {
  const { code, report, stderr } = await audit({
    'policy.json': policy({
      required: [REQUIRE_XCTO],
      exceptions: [{ route: 'bare', header: 'x-content-type-options', reason: 'Good reason.', expires: '2099-12-31' }],
    }),
    'capture.json': capture([{ id: 'bare', headers: [] }]),
  })

  assert.equal(report.summary.errors, 2)
  assert.equal(report.status, 'incomplete')
  assert.equal(code, 2)
  assert.equal(stderr.includes('ERROR   policy.json/exceptions/0 exception-expiry-undecidable'), true)
})

test('exception-reason-missing prints ERROR and counts one error', async () => {
  const { code, report, stderr } = await audit({
    'policy.json': policy({
      required: [REQUIRE_XCTO],
      exceptions: [{ route: 'ok', header: 'x-content-type-options', expires: '2099-12-31' }],
    }),
    'capture.json': capture([OK_ROUTE]),
  }, ['--as-of', '2026-03-01'])

  assert.equal(report.summary.errors, 1)
  assert.equal(report.status, 'incomplete')
  assert.equal(code, 2)
  assert.equal(stderr.includes('ERROR   policy.json/exceptions/0/reason exception-reason-missing'), true)
})

test('exception-route-unknown prints WARNING and counts no error', async () => {
  const { code, report, stderr } = await audit({
    'policy.json': policy({
      required: [REQUIRE_XCTO],
      exceptions: [{ route: 'renamed', header: 'x-content-type-options', reason: 'Stale.', expires: '2099-12-31' }],
    }),
    'capture.json': capture([OK_ROUTE]),
  }, ['--as-of', '2026-03-01'])

  assert.equal(report.summary.errors, 0)
  assert.equal(report.summary.warnings, 1)
  assert.equal(report.status, 'pass')
  assert.equal(code, 0)
  assert.equal(stderr.includes('WARNING policy.json/exceptions/0/route exception-route-unknown'), true)
})

test('exception-unused prints WARNING and counts no error', async () => {
  const { code, report, stderr } = await audit({
    'policy.json': policy({
      required: [REQUIRE_XCTO],
      exceptions: [{ route: 'ok', header: 'x-content-type-options', reason: 'Spare.', expires: '2099-12-31' }],
    }),
    'capture.json': capture([OK_ROUTE]),
  }, ['--as-of', '2026-03-01'])

  assert.equal(report.summary.errors, 0)
  assert.equal(report.summary.warnings, 1)
  assert.equal(report.status, 'pass')
  assert.equal(code, 0)
  assert.equal(stderr.includes('WARNING policy.json/exceptions/0 exception-unused'), true)
})

test('forbidden-header-present prints ERROR and counts one error', async () => {
  const { code, report, stderr } = await audit({
    'policy.json': policy({ forbidden: [{ header: 'x-powered-by' }] }),
    'capture.json': capture([{ id: 'chatty', headers: [{ name: 'X-Powered-By', value: 'Express' }] }]),
  })

  assert.equal(report.summary.errors, 1)
  assert.equal(report.status, 'fail')
  assert.equal(code, 1)
  assert.equal(stderr.includes('ERROR   capture.json/routes/0/headers/0 forbidden-header-present'), true)
})

test('header-duplicated prints ERROR and counts one error', async () => {
  const { code, report, stderr } = await audit({
    'policy.json': policy({ required: [REQUIRE_XCTO] }),
    'capture.json': capture([{ id: 'twice', headers: [XCTO, { name: 'x-content-type-options', value: 'sniff' }] }, OK_ROUTE]),
  })

  assert.equal(report.summary.errors, 1)
  assert.equal(report.status, 'incomplete')
  assert.equal(code, 2)
  assert.equal(stderr.includes('ERROR   capture.json/routes/0/headers/1 header-duplicated'), true)
})

test('header-invalid prints ERROR and counts one error', async () => {
  const { code, report, stderr } = await audit({
    'policy.json': policy({ required: [REQUIRE_XCTO] }),
    'capture.json': capture([{ id: 'malformed', headers: [{ name: 'not a token', value: 'v' }, XCTO] }]),
  })

  assert.equal(report.summary.errors, 1)
  assert.equal(report.status, 'incomplete')
  assert.equal(code, 2)
  assert.equal(stderr.includes('ERROR   capture.json/routes/0/headers/0/name header-invalid'), true)
})

test('header-value-control-character prints ERROR and counts one error', async () => {
  const { code, report, stderr } = await audit({
    'policy.json': policy({ required: [REQUIRE_XCTO] }),
    'capture.json': capture([
      { id: 'injected', headers: [{ name: 'X-Content-Type-Options', value: `nosniff${String.fromCharCode(0x0d)}` }] },
      OK_ROUTE,
    ]),
  })

  assert.equal(report.summary.errors, 1)
  assert.equal(report.status, 'incomplete')
  assert.equal(code, 2)
  assert.equal(stderr.includes('ERROR   capture.json/routes/0/headers/0/value header-value-control-character'), true)
})

test('header-value-too-long prints ERROR and counts one error', async () => {
  const { code, report, stderr } = await audit({
    'policy.json': policy({ required: [REQUIRE_XCTO] }),
    'capture.json': capture([
      { id: 'long', headers: [{ name: 'X-Content-Type-Options', value: 'n'.repeat(40) }] },
      OK_ROUTE,
    ]),
  }, ['--max-header-value-length', '10'])

  assert.equal(report.summary.errors, 1)
  assert.equal(report.status, 'incomplete')
  assert.equal(code, 2)
  assert.equal(stderr.includes('ERROR   capture.json/routes/0/headers/0/value header-value-too-long'), true)
})

test('header-value-unexpected prints ERROR and counts one error', async () => {
  const { code, report, stderr } = await audit({
    'policy.json': policy({ required: [{ header: 'x-content-type-options', allowedValues: ['nosniff'] }] }),
    'capture.json': capture([{ id: 'odd', headers: [{ name: 'X-Content-Type-Options', value: 'sniff-away' }] }]),
  })

  assert.equal(report.summary.errors, 1)
  assert.equal(report.status, 'fail')
  assert.equal(code, 1)
  assert.equal(stderr.includes('ERROR   capture.json/routes/0/headers/0/value header-value-unexpected'), true)
})

test('hsts-directive-duplicate prints ERROR and leaves the field undecided', async () => {
  const { code, report, stderr } = await audit({
    'policy.json': policy({ required: [REQUIRE_HSTS] }),
    'capture.json': capture([hstsRoute('twice', 'max-age=600; max-age=700')]),
  })

  assert.equal(report.summary.warnings, 0)
  assert.equal(report.status, 'incomplete')
  assert.equal(report.routes[0].undecided.includes('strict-transport-security'), true)
  assert.equal(code, 2)
  assert.equal(stderr.includes('ERROR   capture.json/routes/0/headers/0/value hsts-directive-duplicate'), true)
})

test('hsts-directive-unknown prints WARNING and counts no error', async () => {
  const { code, report, stderr } = await audit({
    'policy.json': policy({ required: [REQUIRE_HSTS] }),
    'capture.json': capture([hstsRoute('odd', 'max-age=600; includeSubdomain')]),
  })

  assert.equal(report.summary.errors, 0)
  assert.equal(report.summary.warnings, 1)
  assert.equal(report.status, 'pass')
  assert.equal(code, 0)
  assert.equal(stderr.includes('WARNING capture.json/routes/0/headers/0/value hsts-directive-unknown'), true)
})

test('hsts-include-subdomains-missing prints ERROR and counts one error', async () => {
  const { code, report, stderr } = await audit({
    'policy.json': policy({ required: [{ header: 'strict-transport-security', requireIncludeSubDomains: true }] }),
    'capture.json': capture([hstsRoute('apex', 'max-age=600')]),
  })

  assert.equal(report.summary.errors, 1)
  assert.equal(report.status, 'fail')
  assert.equal(code, 1)
  assert.equal(stderr.includes('ERROR   capture.json/routes/0/headers/0/value hsts-include-subdomains-missing'), true)
})

test('hsts-max-age-malformed prints ERROR and counts one error', async () => {
  const { code, report, stderr } = await audit({
    'policy.json': policy({ required: [REQUIRE_HSTS] }),
    'capture.json': capture([hstsRoute('scientific', 'max-age=1e7')]),
  })

  assert.equal(report.summary.errors, 1)
  assert.equal(report.status, 'fail')
  assert.equal(code, 1)
  assert.equal(stderr.includes('ERROR   capture.json/routes/0/headers/0/value hsts-max-age-malformed'), true)
})

test('hsts-max-age-missing prints ERROR and counts one error', async () => {
  const { code, report, stderr } = await audit({
    'policy.json': policy({ required: [{ header: 'strict-transport-security', minMaxAge: 600 }] }),
    'capture.json': capture([hstsRoute('tokenless', 'includeSubDomains')]),
  })

  assert.equal(report.summary.errors, 1)
  assert.equal(report.status, 'fail')
  assert.equal(code, 1)
  assert.equal(stderr.includes('ERROR   capture.json/routes/0/headers/0/value hsts-max-age-missing'), true)
})

test('hsts-max-age-too-short prints ERROR and counts one error', async () => {
  const { code, report, stderr } = await audit({
    'policy.json': policy({ required: [{ header: 'strict-transport-security', minMaxAge: 600 }] }),
    'capture.json': capture([hstsRoute('brief', 'max-age=300')]),
  })

  assert.equal(report.summary.errors, 1)
  assert.equal(report.status, 'fail')
  assert.equal(code, 1)
  assert.equal(stderr.includes('ERROR   capture.json/routes/0/headers/0/value hsts-max-age-too-short'), true)
})

test('hsts-preload-missing prints ERROR and counts one error', async () => {
  const { code, report, stderr } = await audit({
    'policy.json': policy({ required: [{ header: 'strict-transport-security', requirePreload: true }] }),
    'capture.json': capture([hstsRoute('unlisted', 'max-age=600')]),
  })

  assert.equal(report.summary.errors, 1)
  assert.equal(report.status, 'fail')
  assert.equal(code, 1)
  assert.equal(stderr.includes('ERROR   capture.json/routes/0/headers/0/value hsts-preload-missing'), true)
})

test('identifier-invalid prints ERROR and counts one error', async () => {
  const { code, report, stderr } = await audit({
    'policy.json': policy({ required: [REQUIRE_XCTO] }),
    'capture.json': capture([{ id: 'has space', headers: [] }, OK_ROUTE]),
  })

  assert.equal(report.summary.errors, 1)
  assert.equal(report.status, 'incomplete')
  assert.equal(code, 2)
  assert.equal(stderr.includes('ERROR   capture.json/routes/0/id identifier-invalid'), true)
})

test('input-not-json prints ERROR and counts one error', async () => {
  const { code, report, stderr } = await audit({
    'policy.json': policy({ required: [REQUIRE_XCTO] }),
    'capture.json': '{ this is not json',
  })

  assert.equal(report.summary.errors, 1)
  assert.equal(report.status, 'incomplete')
  assert.equal(code, 2)
  assert.equal(stderr.includes('ERROR   capture.json input-not-json'), true)
})

test('input-not-utf8 prints ERROR and counts one error', async () => {
  const { code, report, stderr } = await audit({
    'policy.json': policy({ required: [REQUIRE_XCTO] }),
    'capture.json': new Uint8Array([0x7b, 0xff, 0xfe, 0x7d]),
  })

  assert.equal(report.summary.errors, 1)
  assert.equal(report.status, 'incomplete')
  assert.equal(code, 2)
  assert.equal(stderr.includes('ERROR   capture.json input-not-utf8'), true)
})

test('input-too-large prints ERROR and counts one error per document', async () => {
  const { code, report, stderr } = await audit({
    'policy.json': policy({ required: [REQUIRE_XCTO] }),
    'capture.json': capture([OK_ROUTE]),
  }, ['--max-file-bytes', '10'])

  assert.equal(report.summary.errors, 2)
  assert.equal(report.status, 'incomplete')
  assert.equal(code, 2)
  assert.equal(stderr.includes('ERROR   capture.json input-too-large'), true)
  assert.equal(stderr.includes('ERROR   policy.json input-too-large'), true)
})

test('input-unreadable prints ERROR and counts one error', async () => {
  const { code, report, stderr } = await audit({
    'policy.json': policy({ required: [REQUIRE_XCTO] }),
  })

  assert.equal(report.summary.errors, 1)
  assert.equal(report.status, 'incomplete')
  assert.equal(code, 2)
  assert.equal(stderr.includes('ERROR   capture.json input-unreadable'), true)
})

test('no-checks-performed prints ERROR and counts one error', async () => {
  const { code, report, stderr } = await audit({
    'policy.json': policy({ required: [], forbidden: [], exceptions: [] }),
    'capture.json': capture([]),
  })

  assert.equal(report.summary.errors, 1)
  assert.equal(report.summary.checked, 0)
  assert.equal(report.status, 'incomplete')
  assert.equal(code, 2)
  assert.equal(stderr.includes('ERROR   policy.json/required no-checks-performed'), true)
})

test('path-escapes-root prints ERROR and counts one error', async () => {
  const { code, report, stderr } = await audit(
    { 'policy.json': policy({ required: [REQUIRE_XCTO] }) },
    [],
    async (root) => {
      const outside = await mkdtemp(join(tmpdir(), 'http-security-header-auditor-out-'))
      await writeFile(join(outside, 'elsewhere.json'), JSON.stringify(capture([OK_ROUTE])))
      await symlink(join(outside, 'elsewhere.json'), join(root, 'capture.json'))
    },
  )

  assert.equal(report.summary.errors, 1)
  assert.equal(report.status, 'incomplete')
  assert.equal(code, 2)
  assert.equal(stderr.includes('ERROR   capture.json path-escapes-root'), true)
})

test('pattern-unsupported prints ERROR and counts one error', async () => {
  const { code, report, stderr } = await audit({
    'policy.json': policy({ required: [REQUIRE_XCTO] }),
    'capture.json': capture([{ id: 'api/*', headers: [] }, OK_ROUTE]),
  })

  assert.equal(report.summary.errors, 1)
  assert.equal(report.status, 'incomplete')
  assert.equal(code, 2)
  assert.equal(stderr.includes('ERROR   capture.json/routes/0/id pattern-unsupported'), true)
})

test('policy-contradiction prints ERROR and counts one error', async () => {
  const { code, report, stderr } = await audit({
    'policy.json': policy({ required: [{ header: 'server' }, REQUIRE_XCTO], forbidden: [{ header: 'server' }] }),
    'capture.json': capture([OK_ROUTE]),
  })

  assert.equal(report.summary.errors, 1)
  assert.equal(report.status, 'incomplete')
  assert.equal(code, 2)
  assert.equal(stderr.includes('ERROR   policy.json/forbidden/0 policy-contradiction'), true)
})

test('policy-invalid prints ERROR and counts one error', async () => {
  const { code, report, stderr } = await audit({
    'policy.json': policy({ required: [{ header: 'x-frame-options', allowedValue: ['deny'] }, REQUIRE_XCTO] }),
    'capture.json': capture([OK_ROUTE]),
  })

  assert.equal(report.summary.errors, 1)
  assert.equal(report.status, 'incomplete')
  assert.equal(code, 2)
  assert.equal(stderr.includes('ERROR   policy.json/required/0 policy-invalid'), true)
})

test('required-header-missing prints ERROR and counts one error', async () => {
  const { code, report, stderr } = await audit({
    'policy.json': policy({ required: [REQUIRE_XCTO] }),
    'capture.json': capture([{ id: 'bare', headers: [] }]),
  })

  assert.equal(report.summary.errors, 1)
  assert.equal(report.status, 'fail')
  assert.equal(code, 1)
  assert.equal(stderr.includes('ERROR   capture.json/routes/0 required-header-missing'), true)
})

test('route-duplicate prints ERROR and counts one error', async () => {
  const { code, report, stderr } = await audit({
    'policy.json': policy({ required: [REQUIRE_XCTO] }),
    'capture.json': capture([OK_ROUTE, OK_ROUTE]),
  })

  assert.equal(report.summary.errors, 1)
  assert.equal(report.status, 'incomplete')
  assert.equal(code, 2)
  assert.equal(stderr.includes('ERROR   capture.json/routes/1/id route-duplicate'), true)
})

test('route-invalid prints ERROR and counts one error', async () => {
  const { code, report, stderr } = await audit({
    'policy.json': policy({ required: [REQUIRE_XCTO] }),
    'capture.json': capture([{ id: 'broken', headers: 'not an array' }, OK_ROUTE]),
  })

  assert.equal(report.summary.errors, 1)
  assert.equal(report.status, 'incomplete')
  assert.equal(code, 2)
  assert.equal(stderr.includes('ERROR   capture.json/routes/0/headers route-invalid'), true)
})

test('schema-version-unsupported prints ERROR and counts one error', async () => {
  const { code, report, stderr } = await audit({
    'policy.json': policy({ required: [REQUIRE_XCTO] }),
    'capture.json': { schemaVersion: '2', routes: [OK_ROUTE] },
  })

  assert.equal(report.summary.errors, 1)
  assert.equal(report.status, 'incomplete')
  assert.equal(code, 2)
  assert.equal(stderr.includes('ERROR   capture.json/schemaVersion schema-version-unsupported'), true)
})

test('too-many-exceptions prints ERROR and counts one error', async () => {
  const { code, report, stderr } = await audit({
    'policy.json': policy({
      required: [REQUIRE_XCTO],
      exceptions: [
        { route: 'ok', header: 'a', reason: 'One.', expires: '2099-12-31' },
        { route: 'ok', header: 'b', reason: 'Two.', expires: '2099-12-31' },
      ],
    }),
    'capture.json': capture([OK_ROUTE]),
  }, ['--max-exceptions', '1'])

  assert.equal(report.summary.errors, 1)
  assert.equal(report.status, 'incomplete')
  assert.equal(code, 2)
  assert.equal(stderr.includes('ERROR   policy.json/exceptions too-many-exceptions'), true)
})

test('too-many-findings prints ERROR and counts one error', async () => {
  const { code, report, stderr } = await audit({
    'policy.json': policy({ required: [REQUIRE_XCTO] }),
    'capture.json': capture([{ id: 'a', headers: [] }, { id: 'b', headers: [] }]),
  }, ['--max-findings', '1'])

  assert.equal(report.summary.errors, 1)
  assert.equal(report.findings.length, 1)
  assert.equal(report.status, 'incomplete')
  assert.equal(code, 2)
  assert.equal(stderr.includes('ERROR   capture.json too-many-findings'), true)
})

test('too-many-headers prints ERROR and counts one error', async () => {
  const { code, report, stderr } = await audit({
    'policy.json': policy({ required: [REQUIRE_XCTO] }),
    'capture.json': capture([{ id: 'fat', headers: [XCTO, { name: 'x-other', value: 'v' }] }, OK_ROUTE]),
  }, ['--max-headers-per-route', '1'])

  assert.equal(report.summary.errors, 1)
  assert.equal(report.status, 'incomplete')
  assert.equal(code, 2)
  assert.equal(stderr.includes('ERROR   capture.json/routes/0/headers too-many-headers'), true)
})

test('too-many-requirements prints ERROR and counts one error', async () => {
  const { code, report, stderr } = await audit({
    'policy.json': policy({ required: [REQUIRE_XCTO, { header: 'referrer-policy' }] }),
    'capture.json': capture([OK_ROUTE]),
  }, ['--max-requirements', '1'])

  assert.equal(report.summary.errors, 1)
  assert.equal(report.status, 'incomplete')
  assert.equal(code, 2)
  assert.equal(stderr.includes('ERROR   policy.json/required too-many-requirements'), true)
})

test('too-many-routes prints ERROR and counts one error', async () => {
  const { code, report, stderr } = await audit({
    'policy.json': policy({ required: [REQUIRE_XCTO] }),
    'capture.json': capture([OK_ROUTE, { id: 'second', headers: [XCTO] }]),
  }, ['--max-routes', '1'])

  assert.equal(report.summary.errors, 1)
  assert.equal(report.status, 'incomplete')
  assert.equal(code, 2)
  assert.equal(stderr.includes('ERROR   capture.json/routes too-many-routes'), true)
})

/**
 * The one rule the binary cannot be made to raise deterministically.
 *
 * `time-budget-exceeded` needs a clock, and the CLI has no flag that injects
 * one -- deliberately, because a tool that lets its caller supply a clock from
 * the command line has a clock in production. So this case drives the exported
 * function with an injected clock and asserts the same three things the cases
 * above assert of the binary: the printed word, the error count, and the exit
 * code the report maps to.
 */
test('time-budget-exceeded prints ERROR and counts one error', async () => {
  const root = await mkdtemp(join(tmpdir(), 'http-security-header-auditor-word-'))
  try {
    await writeFile(join(root, 'policy.json'), JSON.stringify(policy({ required: [REQUIRE_XCTO] })))
    await writeFile(join(root, 'capture.json'), JSON.stringify(capture([OK_ROUTE, { id: 'second', headers: [XCTO] }])))

    let tick = 0
    const report = await auditHeaders({
      root,
      limits: { maxRuntimeMs: 1000 },
      clock: () => {
        tick += 1
        return tick <= 2 ? 0 : 999999
      },
    })

    assert.equal(report.summary.errors, 1)
    assert.equal(report.status, 'incomplete')
    assert.equal(exitCodeFor(report), 2)
    assert.equal(formatReport(report).includes('ERROR   capture.json/routes time-budget-exceeded'), true)
  } finally {
    await rm(root, { recursive: true, force: true })
  }
})
