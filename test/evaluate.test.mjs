import assert from 'node:assert/strict'
import test from 'node:test'

import {
  apiReport,
  clean,
  findingsFor,
  fixture,
  forbid,
  header,
  raisedRules,
  requirement,
  route,
  routeRow,
} from './support.mjs'

test('the clean fixture raises nothing and counts what it checked', async () => {
  const report = await apiReport(clean())

  assert.equal(report.status, 'pass')
  assert.deepEqual(report.findings, [])
  assert.equal(report.summary.checked, 1)
  assert.equal(report.summary.routes, 1)
  assert.equal(report.summary.evaluated, 1)
  assert.equal(routeRow(report, 'ok').verdict, 'pass')
})

test('a missing required field fails, and names both the route and the requirement', async () => {
  const report = await apiReport(fixture(
    { required: [requirement('x-content-type-options', { allowedValues: ['nosniff'] })] },
    [route('bare', [])],
  ))

  assert.equal(report.status, 'fail')
  assert.deepEqual(raisedRules(report), ['required-header-missing'])
  const [finding] = findingsFor(report, 'required-header-missing')
  assert.equal(finding.location.file, 'capture.json')
  assert.equal(finding.location.pointer, '/routes/0')
  assert.equal(finding.message.includes('x-content-type-options'), true)
  assert.equal(finding.message.includes('/required/0'), true)
  assert.deepEqual(routeRow(report, 'bare').missing, ['x-content-type-options'])
})

test('every route is evaluated against every requirement, not just the first', async () => {
  const report = await apiReport(fixture(
    { required: [requirement('x-content-type-options'), requirement('referrer-policy')] },
    [
      route('one', [header('X-Content-Type-Options', 'nosniff'), header('Referrer-Policy', 'no-referrer')]),
      route('two', [header('X-Content-Type-Options', 'nosniff')]),
    ],
  ))

  assert.equal(report.summary.checked, 4)
  assert.equal(report.summary.routesFailing, 1)
  assert.deepEqual(routeRow(report, 'two').missing, ['referrer-policy'])
  assert.equal(routeRow(report, 'one').verdict, 'pass')
})

test('a value outside the allowed set fails and the value is quoted back bounded', async () => {
  const report = await apiReport(fixture(
    { required: [requirement('referrer-policy', { allowedValues: ['no-referrer', 'strict-origin-when-cross-origin'] })] },
    [route('leaky', [header('Referrer-Policy', 'unsafe-url')])],
  ))

  assert.equal(report.status, 'fail')
  const [finding] = findingsFor(report, 'header-value-unexpected')
  assert.equal(finding.evidence, 'unsafe-url')
  assert.equal(finding.location.pointer, '/routes/0/headers/0/value')
})

test('an allowed value is compared case-insensitively and with the surrounding space trimmed', async () => {
  const report = await apiReport(fixture(
    { required: [requirement('x-frame-options', { allowedValues: ['deny'] })] },
    [route('shouty', [header('X-Frame-Options', '  DENY  ')])],
  ))

  assert.equal(report.status, 'pass')
  assert.deepEqual(report.findings, [])
})

test('a forbidden field present fails, and its value is the evidence', async () => {
  const report = await apiReport(fixture(
    { forbidden: [forbid('x-powered-by')] },
    [route('chatty', [header('X-Powered-By', 'Express')])],
  ))

  assert.equal(report.status, 'fail')
  const [finding] = findingsFor(report, 'forbidden-header-present')
  assert.equal(finding.evidence, 'Express')
  assert.equal(report.summary.checked, 1, 'checking a forbidden field is a check, present or not')
})

test('a forbidden field absent is a check that passed', async () => {
  const report = await apiReport(fixture(
    { forbidden: [forbid('x-powered-by')] },
    [route('quiet', [header('X-Content-Type-Options', 'nosniff')])],
  ))

  assert.equal(report.status, 'pass')
  assert.equal(report.summary.checked, 1)
})

test('a required directive that is absent from the policy string is reported', async () => {
  const report = await apiReport(fixture(
    { required: [requirement('content-security-policy', { requiredDirectives: ['default-src', 'frame-ancestors'] })] },
    [route('partial', [header('Content-Security-Policy', "default-src 'self'")])],
  ))

  assert.equal(report.status, 'fail')
  const findings = findingsFor(report, 'csp-directive-missing')
  assert.equal(findings.length, 1)
  assert.equal(findings[0].message.includes('frame-ancestors'), true)
})

test('a forbidden source inside a source-list directive is reported once per directive', async () => {
  const report = await apiReport(fixture(
    { required: [requirement('content-security-policy', { forbiddenSources: ["'unsafe-eval'", "'unsafe-inline'"] })] },
    [route('loose', [header('Content-Security-Policy', "script-src 'self' 'unsafe-inline'; style-src 'unsafe-inline'")])],
  ))

  const findings = findingsFor(report, 'csp-source-forbidden')
  assert.equal(findings.length, 2)
  assert.equal(findings.every((finding) => finding.message.includes("'unsafe-inline'")), true)
})

test('a nonce reaching a finding is named by its class and never by its bytes', async () => {
  const report = await apiReport(fixture(
    { required: [requirement('content-security-policy', { forbiddenSources: ["'unsafe-inline'"] })] },
    [route('mixed', [header('Content-Security-Policy', [
      "default-src 'none' 'nonce-r4nd0mv4lu3'",
      "script-src 'unsafe-inline' 'sha256-Zm9vYmFyYmF6'",
    ].join('; '))])],
  ))

  const serialized = JSON.stringify(report)
  assert.equal(serialized.includes('r4nd0mv4lu3'), false, 'nonce entropy never reaches the report')
  assert.equal(serialized.includes('Zm9vYmFyYmF6'), false, 'hash bytes never reach the report either')
  assert.equal(findingsFor(report, 'csp-none-with-sources')[0].evidence, "'nonce-...'")
  assert.equal(findingsFor(report, 'csp-source-forbidden')[0].message.includes("'unsafe-inline'"), true)
})

test('the contradictions the parser finds are reported through their own rules', async () => {
  const report = await apiReport(fixture(
    { required: [requirement('content-security-policy')] },
    [route('contradictory', [header('Content-Security-Policy', [
      "default-src 'none' https://cdn.example.invalid",
      "script-src 'self' 'unsafe-inline' 'nonce-abc123'",
      'img-src * https://images.example.invalid',
      "img-src 'self'",
    ].join('; '))])],
  ))

  assert.deepEqual(raisedRules(report), [
    'csp-directive-duplicate',
    'csp-none-with-sources',
    'csp-unsafe-inline-with-nonce',
    'csp-wildcard-shadows-sources',
  ])
  assert.equal(report.status, 'fail')
})

test('HSTS is checked against the duration and the tokens the policy asks for', async () => {
  const report = await apiReport(fixture(
    { required: [requirement('strict-transport-security', { minMaxAge: 31536000, requireIncludeSubDomains: true, requirePreload: true })] },
    [route('weak', [header('Strict-Transport-Security', 'max-age=300')])],
  ))

  assert.deepEqual(raisedRules(report), [
    'hsts-include-subdomains-missing',
    'hsts-max-age-too-short',
    'hsts-preload-missing',
  ])
})

test('an HSTS field with no max-age at all is reported as having none', async () => {
  const report = await apiReport(fixture(
    { required: [requirement('strict-transport-security', { minMaxAge: 600 })] },
    [route('tokenless', [header('Strict-Transport-Security', 'includeSubDomains')])],
  ))

  assert.deepEqual(raisedRules(report), ['hsts-max-age-missing'])
})

test('an unreadable max-age is reported once, not twice as unreadable and missing', async () => {
  const report = await apiReport(fixture(
    { required: [requirement('strict-transport-security', { minMaxAge: 600 })] },
    [route('scientific', [header('Strict-Transport-Security', 'max-age=1e7')])],
  ))

  assert.deepEqual(raisedRules(report), ['hsts-max-age-malformed'])
})

test('requireIncludeSubDomains false asks for nothing, and is not read as asking for its absence', async () => {
  const report = await apiReport(fixture(
    { required: [requirement('strict-transport-security', { requireIncludeSubDomains: false })] },
    [route('either-way', [header('Strict-Transport-Security', 'max-age=600; includeSubDomains')])],
  ))

  assert.equal(report.status, 'pass')
  assert.deepEqual(report.findings, [])
})

test('the route row lists the fields present, sorted, and the CSP directives it parsed', async () => {
  const report = await apiReport(fixture(
    { required: [requirement('content-security-policy')] },
    [route('described', [
      header('Referrer-Policy', 'no-referrer'),
      header('Content-Security-Policy', "object-src 'none'; default-src 'self'"),
    ])],
  ))

  const row = routeRow(report, 'described')
  assert.deepEqual(row.headers, ['content-security-policy', 'referrer-policy'])
  assert.deepEqual(row.csp.directives, ['default-src', 'object-src'])
  assert.equal(row.csp.analysed, true)
})

test('two runs over identical inputs produce byte-identical reports', async () => {
  const files = fixture(
    { required: [requirement('content-security-policy', { requiredDirectives: ['frame-ancestors'] })], forbidden: [forbid('server')] },
    [
      route('b', [header('Content-Security-Policy', "default-src 'self'"), header('Server', 'nginx')]),
      route('a', [header('Content-Security-Policy', "frame-ancestors 'none'")]),
    ],
  )

  const first = JSON.stringify(await apiReport(files))
  const second = JSON.stringify(await apiReport(files))
  assert.equal(first, second)
})
