/**
 * The acceptance case: `Content-Security-Policy-Report-Only` enforces nothing.
 *
 * A report-only policy is a diagnostic channel. The browser evaluates the
 * policy, sends a violation report, and then loads the resource anyway. A route
 * carrying only that field has no content security policy in force -- and a
 * reviewer skimming a capture, or a tool matching on a prefix, will conclude
 * otherwise. That is why the distinction gets a file of its own, a rule of its
 * own, and assertions written as literals rather than derived from anything the
 * implementation exports.
 *
 * Every case here drives the real binary and reads the real exit code.
 */

import assert from 'node:assert/strict'
import test from 'node:test'

import { cliReport, header, route } from './support.mjs'

const REQUIRES_CSP = {
  schemaVersion: '1',
  required: [{ header: 'content-security-policy' }],
}

const ENFORCING = "default-src 'self'"
const REPORT_ONLY = "default-src 'self'; report-uri /csp-reports"

test('a route carrying only the report-only field fails the requirement for a policy', async () => {
  const { code, report } = await cliReport({
    'policy.json': REQUIRES_CSP,
    'capture.json': {
      schemaVersion: '1',
      routes: [route('rollout', [header('Content-Security-Policy-Report-Only', REPORT_ONLY)])],
    },
  })

  assert.equal(report.status, 'fail')
  assert.equal(code, 1)
  assert.equal(report.summary.errors, 2)
  assert.equal(report.summary.warnings, 0)
  assert.deepEqual(
    report.findings.map((finding) => finding.ruleId).sort(),
    ['csp-report-only-without-enforcement', 'required-header-missing'],
  )
})

test('the route row says the policy is not enforced and names the field as missing', async () => {
  const { report } = await cliReport({
    'policy.json': REQUIRES_CSP,
    'capture.json': {
      schemaVersion: '1',
      routes: [route('rollout', [header('Content-Security-Policy-Report-Only', REPORT_ONLY)])],
    },
  })

  const row = report.routes[0]
  assert.equal(row.id, 'rollout')
  assert.equal(row.verdict, 'fail')
  assert.equal(row.csp.enforced, false)
  assert.equal(row.csp.reportOnly, true)
  assert.equal(row.csp.analysed, false)
  assert.deepEqual(row.csp.directives, [])
  assert.deepEqual(row.missing, ['content-security-policy'])
  assert.deepEqual(row.headers, ['content-security-policy-report-only'])
})

test('the report-only field is not parsed, so its directives are never credited to the route', async () => {
  const { report } = await cliReport({
    'policy.json': {
      schemaVersion: '1',
      required: [{ header: 'content-security-policy', requiredDirectives: ['default-src', 'frame-ancestors'] }],
    },
    'capture.json': {
      schemaVersion: '1',
      routes: [route('rollout', [header('Content-Security-Policy-Report-Only', "default-src 'self'; frame-ancestors 'none'")])],
    },
  })

  // The report-only field declares both required directives. It satisfies
  // neither, because it enforces neither: the finding is that the field itself
  // is absent, and no directive-level finding is raised about a policy that is
  // not in force.
  assert.deepEqual(
    report.findings.map((finding) => finding.ruleId).sort(),
    ['csp-report-only-without-enforcement', 'required-header-missing'],
  )
  assert.deepEqual(report.routes[0].csp.directives, [])
})

test('an enforcing policy satisfies the requirement and raises nothing', async () => {
  const { code, report } = await cliReport({
    'policy.json': REQUIRES_CSP,
    'capture.json': {
      schemaVersion: '1',
      routes: [route('shipped', [header('Content-Security-Policy', ENFORCING)])],
    },
  })

  assert.equal(report.status, 'pass')
  assert.equal(code, 0)
  assert.equal(report.summary.errors, 0)
  assert.deepEqual(report.findings, [])
  assert.equal(report.routes[0].csp.enforced, true)
  assert.equal(report.routes[0].csp.reportOnly, false)
})

test('both fields together are a policy in force, plus a diagnostic channel beside it', async () => {
  const { code, report } = await cliReport({
    'policy.json': REQUIRES_CSP,
    'capture.json': {
      schemaVersion: '1',
      routes: [route('both', [
        header('Content-Security-Policy', ENFORCING),
        header('Content-Security-Policy-Report-Only', REPORT_ONLY),
      ])],
    },
  })

  assert.equal(report.status, 'pass')
  assert.equal(code, 0)
  assert.deepEqual(report.findings, [])
  assert.equal(report.routes[0].csp.enforced, true)
  assert.equal(report.routes[0].csp.reportOnly, true)
})

test('the rule fires even when the policy never asked for a content security policy', async () => {
  // Shipping report-only alone is a rollout that was never finished, whatever
  // the policy document happens to require. A team that means to stay in
  // report-only says so with a route exception carrying a reason and a date.
  const { code, report } = await cliReport({
    'policy.json': { schemaVersion: '1', required: [{ header: 'x-content-type-options', allowedValues: ['nosniff'] }] },
    'capture.json': {
      schemaVersion: '1',
      routes: [route('rollout', [
        header('Content-Security-Policy-Report-Only', REPORT_ONLY),
        header('X-Content-Type-Options', 'nosniff'),
      ])],
    },
  })

  assert.equal(report.status, 'fail')
  assert.equal(code, 1)
  assert.equal(report.summary.errors, 1)
  assert.deepEqual(report.findings.map((finding) => finding.ruleId), ['csp-report-only-without-enforcement'])
})

test('a waiver on content-security-policy covers the rollout, and says so in the report', async () => {
  const { code, report } = await cliReport({
    'policy.json': {
      schemaVersion: '1',
      required: [{ header: 'content-security-policy' }],
      exceptions: [{
        route: 'rollout',
        header: 'content-security-policy',
        reason: 'Report-only rollout, violations still being triaged.',
        expires: '2026-09-30',
      }],
    },
    'capture.json': {
      schemaVersion: '1',
      routes: [route('rollout', [header('Content-Security-Policy-Report-Only', REPORT_ONLY)])],
    },
  }, ['--as-of', '2026-03-01'])

  assert.equal(report.status, 'pass')
  assert.equal(code, 0)
  assert.equal(report.summary.errors, 0)
  assert.equal(report.summary.exceptionsApplied, 1)
  assert.deepEqual(report.findings.map((finding) => finding.ruleId), ['exception-applied'])
  // The waiver excuses the failure. It does not rewrite the fact: the route row
  // still records that no policy is enforced.
  assert.equal(report.routes[0].csp.enforced, false)
  assert.equal(report.routes[0].verdict, 'waived')
  assert.deepEqual(report.routes[0].missing, ['content-security-policy'])
})

test('a field whose name merely starts with the required one does not satisfy it either', async () => {
  const { code, report } = await cliReport({
    'policy.json': { schemaVersion: '1', required: [{ header: 'x-frame-options', allowedValues: ['deny'] }] },
    'capture.json': {
      schemaVersion: '1',
      routes: [route('prefixed', [header('X-Frame-Options-Legacy', 'DENY')])],
    },
  })

  assert.equal(report.status, 'fail')
  assert.equal(code, 1)
  assert.deepEqual(report.findings.map((finding) => finding.ruleId), ['required-header-missing'])
})

test('field names are matched case-insensitively, which is what HTTP says they are', async () => {
  const { code, report } = await cliReport({
    'policy.json': { schemaVersion: '1', required: [{ header: 'Content-Security-Policy' }] },
    'capture.json': {
      schemaVersion: '1',
      routes: [route('shouty', [header('CONTENT-SECURITY-POLICY', ENFORCING)])],
    },
  })

  assert.equal(report.status, 'pass')
  assert.equal(code, 0)
})
