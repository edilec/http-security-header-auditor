/**
 * The report envelope and the finding shape, checked against the catalog's
 * report contract.
 *
 * These are the properties a consumer depends on across every tool in the
 * catalog: stdout parses as JSON and carries nothing else, `status` is one of
 * three words, `location.file` is relative to the declared root and never an
 * absolute host path, and every optional field is either absent or bounded.
 */

import assert from 'node:assert/strict'
import { isAbsolute } from 'node:path'
import test from 'node:test'

import {
  EXCERPT_LIMIT,
  REPORT_SCHEMA_VERSION,
  TOOL_ID,
  compareFindings,
  createFinding,
  serializeReport,
} from '../src/index.mjs'
import { apiReport, cliReport, clean, exception, fixture, forbid, header, requirement, route } from './support.mjs'

const MESSAGE_LIMIT = 400
const SUGGESTION_LIMIT = 300
const STATUSES = ['fail', 'incomplete', 'pass']
const SEVERITIES = ['error', 'info', 'warning']

/** A capture that raises a wide spread of rules at once, so the shape check is not run on one finding. */
const BUSY = () => fixture(
  {
    required: [
      requirement('content-security-policy', { requiredDirectives: ['frame-ancestors'], forbiddenSources: ["'unsafe-inline'"] }),
      requirement('strict-transport-security', { minMaxAge: 31536000, requireIncludeSubDomains: true }),
      requirement('referrer-policy', { allowedValues: ['no-referrer'] }),
    ],
    forbidden: [forbid('x-powered-by')],
    exceptions: [
      exception('gone', 'referrer-policy', 'Route was renamed.', '2099-12-31'),
      exception('app', 'x-powered-by', 'Edge proxy, removal tracked.', '2025-01-01'),
    ],
  },
  [
    route('app', [
      header('Content-Security-Policy', "default-src 'none' https://a.example.invalid; script-src 'unsafe-inline' 'nonce-abc'; img-src * https://b.example.invalid; img-src 'self'"),
      header('Strict-Transport-Security', 'max-age=300'),
      header('Referrer-Policy', 'unsafe-url'),
      header('X-Powered-By', 'Express'),
    ]),
    route('bare', []),
  ],
)

test('the envelope carries exactly the documented top-level fields', async () => {
  const report = await apiReport(clean())

  assert.deepEqual(Object.keys(report), ['schemaVersion', 'tool', 'status', 'asOf', 'summary', 'routes', 'findings'])
  assert.equal(report.schemaVersion, REPORT_SCHEMA_VERSION)
  assert.equal(report.tool, TOOL_ID)
  assert.equal(TOOL_ID, 'http-security-header-auditor')
  assert.equal(STATUSES.includes(report.status), true)
})

test('every summary field is an integer, and the counts add up to the findings', async () => {
  const report = await apiReport(BUSY(), { asOf: '2026-03-01' })

  for (const [name, value] of Object.entries(report.summary)) {
    assert.equal(Number.isInteger(value), true, `summary.${name} must be an integer`)
    assert.equal(value >= 0, true, `summary.${name} must not be negative`)
  }

  const errors = report.findings.filter((finding) => finding.severity === 'error').length
  const warnings = report.findings.filter((finding) => finding.severity === 'warning').length
  assert.equal(report.summary.errors, errors)
  assert.equal(report.summary.warnings, warnings)
  assert.equal(report.summary.evaluated + report.summary.unevaluated, report.summary.routes)
})

test('every finding carries the documented shape, bounded, with no absolute path', async () => {
  const report = await apiReport(BUSY(), { asOf: '2026-03-01' })

  assert.equal(report.findings.length > 8, true, 'this fixture must raise a spread of rules for the check to mean anything')
  for (const finding of report.findings) {
    assert.deepEqual(
      Object.keys(finding).filter((key) => !['evidence', 'suggestion'].includes(key)),
      ['ruleId', 'severity', 'message', 'location'],
    )
    assert.match(finding.ruleId, /^[a-z][a-z0-9-]*[a-z0-9]$/)
    assert.equal(SEVERITIES.includes(finding.severity), true)
    assert.equal(typeof finding.message, 'string')
    assert.equal(finding.message.length > 0 && finding.message.length <= MESSAGE_LIMIT + 3, true)

    assert.deepEqual(Object.keys(finding.location), ['file', 'pointer'])
    assert.equal(['policy.json', 'capture.json'].includes(finding.location.file), true)
    assert.equal(isAbsolute(finding.location.file), false, 'location.file is relative to the declared root')
    assert.match(finding.location.pointer, /^(\/[A-Za-z0-9]+)*$/)

    if (Object.hasOwn(finding, 'evidence')) {
      assert.equal(typeof finding.evidence, 'string')
      assert.equal(finding.evidence.length > 0 && finding.evidence.length <= EXCERPT_LIMIT + 3, true)
    }
    if (Object.hasOwn(finding, 'suggestion')) {
      assert.equal(typeof finding.suggestion, 'string')
      assert.equal(finding.suggestion.length > 0 && finding.suggestion.length <= SUGGESTION_LIMIT + 3, true)
    }
  }
})

test('every route row carries the documented shape', async () => {
  const report = await apiReport(BUSY(), { asOf: '2026-03-01' })

  for (const row of report.routes) {
    assert.deepEqual(Object.keys(row), ['id', 'verdict', 'headers', 'missing', 'waived', 'undecided', 'csp'])
    assert.equal(['fail', 'pass', 'undecided', 'waived'].includes(row.verdict), true)
    for (const list of [row.headers, row.missing, row.waived, row.undecided]) {
      assert.equal(Array.isArray(list), true)
      for (const name of list) assert.match(name, /^[!#$%&'*+.^_`|~0-9a-z-]+$/, 'field names are folded tokens')
    }
    assert.deepEqual(Object.keys(row.csp), ['enforced', 'reportOnly', 'analysed', 'directives'])
    assert.equal(typeof row.csp.enforced, 'boolean')
    assert.equal(typeof row.csp.reportOnly, 'boolean')
    assert.equal(typeof row.csp.analysed, 'boolean')
    for (const name of row.csp.directives) assert.match(name, /^[a-z0-9-]+$/)
  }
})

test('findings come back in the documented sort order', async () => {
  const report = await apiReport(BUSY(), { asOf: '2026-03-01' })

  const sorted = [...report.findings].sort(compareFindings)
  assert.deepEqual(report.findings, sorted)
})

test('stdout parses as JSON and carries the report and nothing else', async () => {
  const { stdout, stderr } = await cliReport(BUSY(), ['--as-of', '2026-03-01'])

  const parsed = JSON.parse(stdout)
  assert.equal(parsed.tool, TOOL_ID)
  assert.equal(stdout.endsWith(String.fromCharCode(0x0a)), true)
  assert.equal(`${serializeReport(parsed)}${String.fromCharCode(0x0a)}`, stdout, 'stdout is exactly the serialized report')
  assert.equal(stderr, '', '--json leaves stderr for diagnostics only, and there were none')
})

test('createFinding refuses a rule id that is not in the table', () => {
  assert.throws(
    () => createFinding({ ruleId: 'invented-rule', severity: 'info', message: 'x', file: 'capture.json', pointer: '' }),
    /is not in RULE_SEVERITY/,
  )
})

test('createFinding takes severity from the table and ignores any severity handed to it', () => {
  const finding = createFinding({
    ruleId: 'required-header-missing',
    severity: 'info',
    message: 'a required field is missing',
    file: 'capture.json',
    pointer: '/routes/0',
  })

  assert.equal(finding.severity, 'error')
})

test('an empty evidence string is omitted rather than emitted as an empty field', () => {
  const finding = createFinding({
    ruleId: 'required-header-missing',
    message: 'x',
    file: 'capture.json',
    pointer: '',
    evidence: '',
  })

  assert.equal(Object.hasOwn(finding, 'evidence'), false)
})

test('compareFindings orders by file, then pointer, then rule id, then message', () => {
  const at = (file, pointer, ruleId, message) => ({ location: { file, pointer }, ruleId, message })

  assert.equal(compareFindings(at('a', '/x', 'r', 'm'), at('b', '/a', 'a', 'a')) < 0, true, 'file decides first')
  assert.equal(compareFindings(at('a', '/a', 'r', 'm'), at('a', '/b', 'a', 'a')) < 0, true, 'then pointer')
  assert.equal(compareFindings(at('a', '/a', 'a', 'm'), at('a', '/a', 'b', 'a')) < 0, true, 'then rule id')
  assert.equal(compareFindings(at('a', '/a', 'a', 'a'), at('a', '/a', 'a', 'b')) < 0, true, 'then message')
  assert.equal(compareFindings(at('a', '/a', 'a', 'a'), at('a', '/a', 'a', 'a')), 0)
})
