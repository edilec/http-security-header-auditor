/**
 * Severity pinned by the exit code, for every rule where a demotion would flip
 * the build from red to green.
 *
 * These are the rules that *complete* the run: the evidence was obtained, the
 * verdict was reached, and the only thing deciding whether the process exits 1
 * or 0 is whether the rule is an error. Demote any one of them and its case here
 * stops failing -- which is precisely the defect this file exists to catch, and
 * precisely the one that three agreeing declarations cannot catch, because an
 * exit code is not a declaration and cannot be edited.
 *
 * Nothing in this file imports a severity table, a rule list or a fixture
 * builder. Every expectation is a literal written where it is asserted.
 */

import assert from 'node:assert/strict'
import { execFile } from 'node:child_process'
import { mkdtemp, rm, writeFile } from 'node:fs/promises'
import { tmpdir } from 'node:os'
import { dirname, join } from 'node:path'
import test from 'node:test'
import { fileURLToPath } from 'node:url'
import { promisify } from 'node:util'

const execFileAsync = promisify(execFile)
const CLI = join(dirname(fileURLToPath(import.meta.url)), '../bin/http-security-header-auditor.mjs')

async function audit(policy, capture, extraArgs = []) {
  const root = await mkdtemp(join(tmpdir(), 'http-security-header-auditor-exit-'))
  try {
    await writeFile(join(root, 'policy.json'), JSON.stringify(policy))
    await writeFile(join(root, 'capture.json'), JSON.stringify(capture))
    try {
      const { stdout } = await execFileAsync(process.execPath, [CLI, '--root', root, '--json', ...extraArgs])
      return { code: 0, report: JSON.parse(stdout) }
    } catch (error) {
      return { code: error.code, report: JSON.parse(error.stdout) }
    }
  } finally {
    await rm(root, { recursive: true, force: true })
  }
}

test('required-header-missing exits 1', async () => {
  const { code, report } = await audit(
    { schemaVersion: '1', required: [{ header: 'x-content-type-options' }] },
    { schemaVersion: '1', routes: [{ id: 'bare', headers: [] }] },
  )

  assert.equal(report.status, 'fail')
  assert.equal(report.summary.errors, 1)
  assert.equal(code, 1)
})

test('forbidden-header-present exits 1', async () => {
  const { code, report } = await audit(
    { schemaVersion: '1', forbidden: [{ header: 'x-powered-by' }] },
    { schemaVersion: '1', routes: [{ id: 'chatty', headers: [{ name: 'X-Powered-By', value: 'Express' }] }] },
  )

  assert.equal(report.status, 'fail')
  assert.equal(report.summary.errors, 1)
  assert.equal(code, 1)
})

test('header-value-unexpected exits 1', async () => {
  const { code, report } = await audit(
    { schemaVersion: '1', required: [{ header: 'x-content-type-options', allowedValues: ['nosniff'] }] },
    { schemaVersion: '1', routes: [{ id: 'odd', headers: [{ name: 'X-Content-Type-Options', value: 'sniff-away' }] }] },
  )

  assert.equal(report.status, 'fail')
  assert.equal(report.summary.errors, 1)
  assert.equal(code, 1)
})

test('csp-report-only-without-enforcement exits 1', async () => {
  const { code, report } = await audit(
    { schemaVersion: '1', required: [{ header: 'x-content-type-options' }] },
    {
      schemaVersion: '1',
      routes: [{
        id: 'rollout',
        headers: [
          { name: 'Content-Security-Policy-Report-Only', value: "default-src 'self'" },
          { name: 'X-Content-Type-Options', value: 'nosniff' },
        ],
      }],
    },
  )

  assert.equal(report.status, 'fail')
  assert.equal(report.summary.errors, 1)
  assert.equal(code, 1)
})

test('csp-directive-missing exits 1', async () => {
  const { code, report } = await audit(
    { schemaVersion: '1', required: [{ header: 'content-security-policy', requiredDirectives: ['frame-ancestors'] }] },
    { schemaVersion: '1', routes: [{ id: 'partial', headers: [{ name: 'Content-Security-Policy', value: "default-src 'self'" }] }] },
  )

  assert.equal(report.status, 'fail')
  assert.equal(report.summary.errors, 1)
  assert.equal(code, 1)
})

test('csp-directive-duplicate exits 1', async () => {
  const { code, report } = await audit(
    { schemaVersion: '1', required: [{ header: 'content-security-policy' }] },
    { schemaVersion: '1', routes: [{ id: 'twice', headers: [{ name: 'Content-Security-Policy', value: "img-src 'self'; img-src 'self'" }] }] },
  )

  assert.equal(report.status, 'fail')
  assert.equal(report.summary.errors, 1)
  assert.equal(code, 1)
})

test('csp-directive-malformed exits 1', async () => {
  const { code, report } = await audit(
    { schemaVersion: '1', required: [{ header: 'content-security-policy' }] },
    { schemaVersion: '1', routes: [{ id: 'typo', headers: [{ name: 'Content-Security-Policy', value: "default-src 'self'; script_src 'self'" }] }] },
  )

  assert.equal(report.status, 'fail')
  assert.equal(report.summary.errors, 1)
  assert.equal(code, 1)
})

test('csp-none-with-sources exits 1', async () => {
  const { code, report } = await audit(
    { schemaVersion: '1', required: [{ header: 'content-security-policy' }] },
    { schemaVersion: '1', routes: [{ id: 'both', headers: [{ name: 'Content-Security-Policy', value: "default-src 'none' https://a.example.invalid" }] }] },
  )

  assert.equal(report.status, 'fail')
  assert.equal(report.summary.errors, 1)
  assert.equal(code, 1)
})

test('csp-unsafe-inline-with-nonce exits 1', async () => {
  const { code, report } = await audit(
    { schemaVersion: '1', required: [{ header: 'content-security-policy' }] },
    { schemaVersion: '1', routes: [{ id: 'mixed', headers: [{ name: 'Content-Security-Policy', value: "script-src 'unsafe-inline' 'nonce-abc'" }] }] },
  )

  assert.equal(report.status, 'fail')
  assert.equal(report.summary.errors, 1)
  assert.equal(code, 1)
})

test('csp-source-forbidden exits 1', async () => {
  const { code, report } = await audit(
    { schemaVersion: '1', required: [{ header: 'content-security-policy', forbiddenSources: ["'unsafe-eval'"] }] },
    { schemaVersion: '1', routes: [{ id: 'loose', headers: [{ name: 'Content-Security-Policy', value: "script-src 'unsafe-eval'" }] }] },
  )

  assert.equal(report.status, 'fail')
  assert.equal(report.summary.errors, 1)
  assert.equal(code, 1)
})

test('hsts-max-age-missing exits 1', async () => {
  const { code, report } = await audit(
    { schemaVersion: '1', required: [{ header: 'strict-transport-security', minMaxAge: 600 }] },
    { schemaVersion: '1', routes: [{ id: 'tokenless', headers: [{ name: 'Strict-Transport-Security', value: 'includeSubDomains' }] }] },
  )

  assert.equal(report.status, 'fail')
  assert.equal(report.summary.errors, 1)
  assert.equal(code, 1)
})

test('hsts-max-age-too-short exits 1', async () => {
  const { code, report } = await audit(
    { schemaVersion: '1', required: [{ header: 'strict-transport-security', minMaxAge: 600 }] },
    { schemaVersion: '1', routes: [{ id: 'brief', headers: [{ name: 'Strict-Transport-Security', value: 'max-age=300' }] }] },
  )

  assert.equal(report.status, 'fail')
  assert.equal(report.summary.errors, 1)
  assert.equal(code, 1)
})

test('hsts-max-age-malformed exits 1', async () => {
  const { code, report } = await audit(
    { schemaVersion: '1', required: [{ header: 'strict-transport-security' }] },
    { schemaVersion: '1', routes: [{ id: 'scientific', headers: [{ name: 'Strict-Transport-Security', value: 'max-age=1e7' }] }] },
  )

  assert.equal(report.status, 'fail')
  assert.equal(report.summary.errors, 1)
  assert.equal(code, 1)
})

test('hsts-include-subdomains-missing exits 1', async () => {
  const { code, report } = await audit(
    { schemaVersion: '1', required: [{ header: 'strict-transport-security', requireIncludeSubDomains: true }] },
    { schemaVersion: '1', routes: [{ id: 'apex-only', headers: [{ name: 'Strict-Transport-Security', value: 'max-age=600' }] }] },
  )

  assert.equal(report.status, 'fail')
  assert.equal(report.summary.errors, 1)
  assert.equal(code, 1)
})

test('hsts-preload-missing exits 1', async () => {
  const { code, report } = await audit(
    { schemaVersion: '1', required: [{ header: 'strict-transport-security', requirePreload: true }] },
    { schemaVersion: '1', routes: [{ id: 'unlisted', headers: [{ name: 'Strict-Transport-Security', value: 'max-age=600' }] }] },
  )

  assert.equal(report.status, 'fail')
  assert.equal(report.summary.errors, 1)
  assert.equal(code, 1)
})

test('exception-expired exits 1', async () => {
  const { code, report } = await audit(
    {
      schemaVersion: '1',
      required: [{ header: 'x-content-type-options' }],
      exceptions: [{ route: 'bare', header: 'x-content-type-options', reason: 'Overdue.', expires: '2025-01-31' }],
    },
    { schemaVersion: '1', routes: [{ id: 'bare', headers: [] }] },
    ['--as-of', '2026-03-01'],
  )

  assert.equal(report.status, 'fail')
  assert.equal(report.summary.errors, 2)
  assert.equal(code, 1)
})

/**
 * The other side of the same guarantee: the rules that are *not* errors.
 *
 * Promote any of these to `error` and the run below stops exiting 0. That
 * matters as much as the demotions above: a tool that fails a build over a spare
 * waiver or a directive it has never heard of is a tool people turn off.
 */

test('csp-directive-unknown exits 0', async () => {
  const { code, report } = await audit(
    { schemaVersion: '1', required: [{ header: 'content-security-policy' }] },
    { schemaVersion: '1', routes: [{ id: 'future', headers: [{ name: 'Content-Security-Policy', value: "future-directive 'self'" }] }] },
  )

  assert.equal(report.status, 'pass')
  assert.equal(report.summary.errors, 0)
  assert.equal(report.summary.warnings, 1)
  assert.equal(code, 0)
})

test('csp-source-duplicate exits 0', async () => {
  const { code, report } = await audit(
    { schemaVersion: '1', required: [{ header: 'content-security-policy' }] },
    { schemaVersion: '1', routes: [{ id: 'repeated', headers: [{ name: 'Content-Security-Policy', value: "script-src 'self' 'self'" }] }] },
  )

  assert.equal(report.status, 'pass')
  assert.equal(report.summary.errors, 0)
  assert.equal(report.summary.warnings, 1)
  assert.equal(code, 0)
})

test('csp-wildcard-shadows-sources exits 0', async () => {
  const { code, report } = await audit(
    { schemaVersion: '1', required: [{ header: 'content-security-policy' }] },
    { schemaVersion: '1', routes: [{ id: 'wide', headers: [{ name: 'Content-Security-Policy', value: 'img-src * https://a.example.invalid' }] }] },
  )

  assert.equal(report.status, 'pass')
  assert.equal(report.summary.errors, 0)
  assert.equal(report.summary.warnings, 1)
  assert.equal(code, 0)
})

test('hsts-directive-duplicate exits 0', async () => {
  const { code, report } = await audit(
    { schemaVersion: '1', required: [{ header: 'strict-transport-security' }] },
    { schemaVersion: '1', routes: [{ id: 'twice', headers: [{ name: 'Strict-Transport-Security', value: 'max-age=600; max-age=700' }] }] },
  )

  assert.equal(report.status, 'pass')
  assert.equal(report.summary.errors, 0)
  assert.equal(report.summary.warnings, 1)
  assert.equal(code, 0)
})

test('hsts-directive-unknown exits 0', async () => {
  const { code, report } = await audit(
    { schemaVersion: '1', required: [{ header: 'strict-transport-security' }] },
    { schemaVersion: '1', routes: [{ id: 'odd', headers: [{ name: 'Strict-Transport-Security', value: 'max-age=600; includeSubdomain' }] }] },
  )

  assert.equal(report.status, 'pass')
  assert.equal(report.summary.errors, 0)
  assert.equal(report.summary.warnings, 1)
  assert.equal(code, 0)
})

test('exception-route-unknown exits 0', async () => {
  const { code, report } = await audit(
    {
      schemaVersion: '1',
      required: [{ header: 'x-content-type-options' }],
      exceptions: [{ route: 'renamed', header: 'x-content-type-options', reason: 'Stale.', expires: '2099-12-31' }],
    },
    { schemaVersion: '1', routes: [{ id: 'ok', headers: [{ name: 'X-Content-Type-Options', value: 'nosniff' }] }] },
    ['--as-of', '2026-03-01'],
  )

  assert.equal(report.status, 'pass')
  assert.equal(report.summary.errors, 0)
  assert.equal(report.summary.warnings, 1)
  assert.equal(code, 0)
})

test('exception-unused exits 0', async () => {
  const { code, report } = await audit(
    {
      schemaVersion: '1',
      required: [{ header: 'x-content-type-options' }],
      exceptions: [{ route: 'ok', header: 'x-content-type-options', reason: 'No longer needed.', expires: '2099-12-31' }],
    },
    { schemaVersion: '1', routes: [{ id: 'ok', headers: [{ name: 'X-Content-Type-Options', value: 'nosniff' }] }] },
    ['--as-of', '2026-03-01'],
  )

  assert.equal(report.status, 'pass')
  assert.equal(report.summary.errors, 0)
  assert.equal(report.summary.warnings, 1)
  assert.equal(code, 0)
})

test('exception-applied exits 0 and is neither an error nor a warning', async () => {
  const { code, report } = await audit(
    {
      schemaVersion: '1',
      required: [{ header: 'x-content-type-options' }],
      exceptions: [{ route: 'bare', header: 'x-content-type-options', reason: 'Migration scheduled.', expires: '2099-12-31' }],
    },
    { schemaVersion: '1', routes: [{ id: 'bare', headers: [] }] },
    ['--as-of', '2026-03-01'],
  )

  assert.equal(report.status, 'pass')
  assert.equal(report.summary.errors, 0)
  assert.equal(report.summary.warnings, 0)
  assert.equal(report.findings.length, 1)
  assert.equal(code, 0)
})
