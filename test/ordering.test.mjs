/**
 * Ordering, pinned by what the tool emits.
 *
 * A source scan for `.localeCompare(` is not a determinism test: `Intl.Collator`
 * collates identically and spells differently, so the scan passes while the
 * output silently starts depending on the ICU data of whichever Node build is
 * running. Pinning the comparator itself is no better -- every call site can be
 * swapped on its own, and there are twenty-one of them in this package.
 *
 * Every case below chooses inputs an English collator orders the other way
 * round, pushes them through the real report path, and asserts the exact emitted
 * sequence, so that swapping any one site fails a test rather than going
 * unnoticed. The collator is constructed here and asserted to disagree, which is
 * what makes these cases cases at all.
 *
 * Six sites order values drawn from alphabets on which code-unit order and
 * English collation agree on every pair -- CSP directive names over
 * `[a-z0-9-]`, rule ids and JSON Pointers. Those are proved equivalent by
 * enumeration in `test/ordering-equivalence.test.mjs` rather than left as gaps.
 */

import assert from 'node:assert/strict'
import test from 'node:test'

import { auditHeaders, validateLimits } from '../src/index.mjs'
import {
  apiReport,
  cliReport,
  exception,
  findingsFor,
  fixture,
  forbid,
  header,
  requirement,
  route,
  routeRow,
  withRoot,
} from './support.mjs'

const collator = new Intl.Collator('en')
const disagrees = (left, right) => {
  assert.equal(left < right, true, `${left} precedes ${right} by code unit`)
  assert.equal(collator.compare(left, right) > 0, true, `a collator puts ${right} first, which is what makes this a case`)
}

const collated = (list) => [...list].sort((left, right) => collator.compare(left, right))

test('the disagreements every case below relies on are real', () => {
  disagrees('Z-route', 'a-route')
  disagrees('x-audit', 'x_audit')
  disagrees('README', 'assets')
  disagrees('Z.json', 'a.json')
  disagrees('Z-src', 'a-src')
})

test('the route rows are ordered by route id, by code unit', async () => {
  const report = await apiReport(fixture(
    { required: [requirement('x-content-type-options')] },
    [
      route('a-route', [header('X-Content-Type-Options', 'nosniff')]),
      route('README', [header('X-Content-Type-Options', 'nosniff')]),
      route('Z-route', [header('X-Content-Type-Options', 'nosniff')]),
      route('assets', [header('X-Content-Type-Options', 'nosniff')]),
    ],
  ))

  const ids = report.routes.map((row) => row.id)
  assert.deepEqual(ids, ['README', 'Z-route', 'a-route', 'assets'])
  assert.notDeepEqual(ids, collated(ids), 'a collator would order this list differently')
})

test('the fields a route carries are ordered by field name, by code unit', async () => {
  const report = await apiReport(fixture(
    { required: [requirement('x-content-type-options')] },
    [route('one', [
      header('x_audit', 'b'),
      header('X-Content-Type-Options', 'nosniff'),
      header('x-audit', 'a'),
    ])],
  ))

  const headers = routeRow(report, 'one').headers
  assert.deepEqual(headers, ['x-audit', 'x-content-type-options', 'x_audit'])
  assert.notDeepEqual(headers, collated(headers))
})

test('the missing list is ordered by field name, by code unit', async () => {
  const report = await apiReport(fixture(
    { required: [requirement('x_audit'), requirement('x-audit')] },
    [route('bare', [])],
  ))

  const missing = routeRow(report, 'bare').missing
  assert.deepEqual(missing, ['x-audit', 'x_audit'])
  assert.notDeepEqual(missing, collated(missing))
})

test('the waived list is ordered by field name, by code unit', async () => {
  const report = await apiReport(fixture(
    {
      required: [requirement('x_audit'), requirement('x-audit')],
      exceptions: [
        exception('bare', 'x_audit', 'Second field.', '2099-12-31'),
        exception('bare', 'x-audit', 'First field.', '2099-12-31'),
      ],
    },
    [route('bare', [])],
  ), { asOf: '2026-03-01' })

  const waived = routeRow(report, 'bare').waived
  assert.deepEqual(waived, ['x-audit', 'x_audit'])
  assert.notDeepEqual(waived, collated(waived))
})

test('the undecided list is ordered by field name, by code unit', async () => {
  const report = await apiReport(fixture(
    { required: [requirement('x_audit'), requirement('x-audit')] },
    [route('twice', [
      header('x_audit', 'a'), header('x_audit', 'b'),
      header('x-audit', 'a'), header('x-audit', 'b'),
    ])],
  ))

  const undecided = routeRow(report, 'twice').undecided
  assert.deepEqual(undecided, ['x-audit', 'x_audit'])
  assert.notDeepEqual(undecided, collated(undecided))
})

test('findings are ordered by file first, by code unit', async () => {
  const report = await apiReport({
    'Z.json': { schemaVersion: '1', required: [{ header: 'x-content-type-options' }], exceptions: [{ route: 'missing-route', header: 'x-content-type-options', reason: 'Stale waiver.', expires: '2099-12-31' }] },
    'a.json': { schemaVersion: '1', routes: [{ id: 'bare', headers: [] }] },
  }, { policy: 'Z.json', capture: 'a.json', asOf: '2026-03-01' })

  const files = report.findings.map((finding) => finding.location.file)
  assert.deepEqual(files, ['Z.json', 'a.json'])
  assert.notDeepEqual(files, collated(files))
})

test('findings sharing a file and a pointer are ordered by message, by code unit', async () => {
  const report = await apiReport(fixture(
    { required: [requirement('x_audit'), requirement('x-audit')] },
    [route('bare', [])],
  ))

  const findings = findingsFor(report, 'required-header-missing')
  assert.equal(findings.length, 2)
  assert.deepEqual(findings.map((finding) => finding.location.pointer), ['/routes/0', '/routes/0'])

  const messages = findings.map((finding) => finding.message)
  assert.equal(messages[0].includes('"x-audit"'), true, 'the hyphenated field comes first by code unit')
  assert.equal(messages[1].includes('"x_audit"'), true)
  assert.notDeepEqual(messages, collated(messages), 'a collator would print these two the other way round')
})

test("the sources a 'none' contradiction names are ordered by code unit", async () => {
  const report = await apiReport(fixture(
    { required: [requirement('content-security-policy')] },
    [route('csp', [header('Content-Security-Policy', "default-src 'none' https://a-src.example.invalid https://Z-src.example.invalid")])],
  ))

  const [finding] = findingsFor(report, 'csp-none-with-sources')
  assert.equal(finding.evidence, 'https://Z-src.example.invalid https://a-src.example.invalid')
  assert.notDeepEqual(
    finding.evidence.split(' '),
    collated(finding.evidence.split(' ')),
  )
})

test('the sources a wildcard shadows are ordered by code unit', async () => {
  const report = await apiReport(fixture(
    { required: [requirement('content-security-policy')] },
    [route('csp', [header('Content-Security-Policy', 'img-src * https://a-src.example.invalid https://Z-src.example.invalid')])],
  ))

  const [finding] = findingsFor(report, 'csp-wildcard-shadows-sources')
  assert.equal(finding.evidence, 'https://Z-src.example.invalid https://a-src.example.invalid')
})

test('unknown document keys are listed in code-unit order', async () => {
  const report = await apiReport({
    'policy.json': { schemaVersion: '1', 'x_audit': 1, 'x-audit': 1, required: [] },
    'capture.json': { schemaVersion: '1', routes: [] },
  })

  const [finding] = findingsFor(report, 'document-invalid')
  assert.equal(finding.message.includes('"x-audit", "x_audit"'), true)
  assert.equal(finding.message.includes('"x_audit", "x-audit"'), false)
})

test('the allowed values a rejected field is measured against are listed in code-unit order', async () => {
  const report = await apiReport(fixture(
    { required: [requirement('referrer-policy', { allowedValues: ['x_audit', 'x-audit'] })] },
    [route('odd', [header('Referrer-Policy', 'unsafe-url')])],
  ))

  const [finding] = findingsFor(report, 'header-value-unexpected')
  assert.equal(finding.message.includes('x-audit, x_audit'), true)
  assert.equal(finding.message.includes('x_audit, x-audit'), false)
})

test('which unknown option is named first is decided by code unit', async () => {
  await assert.rejects(
    () => auditHeaders({ root: '.', x_audit: 1, 'x-audit': 1 }),
    /Unknown option "x-audit"/,
  )
})

test('which unknown limit is named first is decided by code unit', () => {
  assert.throws(() => validateLimits({ x_audit: 1, 'x-audit': 1 }), /Unknown limit "x-audit"/)
})

test('the known-limit list the error prints is ordered by code unit, not by collation', () => {
  // A collator folds case before it compares, so it reads these two as
  // "maxheadervaluelength" and "maxheadersperroute" and puts the second first.
  disagrees('maxHeaderValueLength', 'maxHeadersPerRoute')

  let message = ''
  try {
    validateLimits({ nope: 1 })
  } catch (error) {
    message = error.message
  }
  assert.equal(message.includes('maxHeaderValueLength, maxHeadersPerRoute'), true)
  assert.equal(message.includes('maxHeadersPerRoute, maxHeaderValueLength'), false)
})

test('misplaced requirement options are listed in code-unit order, not collated order', async () => {
  disagrees('requireIncludeSubDomains', 'requiredDirectives')

  const report = await apiReport({
    'policy.json': {
      schemaVersion: '1',
      required: [{ header: 'x-frame-options', requiredDirectives: ['default-src'], requireIncludeSubDomains: true }],
    },
    'capture.json': { schemaVersion: '1', routes: [{ id: 'any', headers: [] }] },
  })

  const [finding] = findingsFor(report, 'policy-invalid')
  assert.equal(finding.message.includes('"requireIncludeSubDomains", "requiredDirectives"'), true)
  assert.equal(finding.message.includes('"requiredDirectives", "requireIncludeSubDomains"'), false)
})

test('two forbidden fields on one route produce findings ordered by pointer, by code unit', async () => {
  const report = await apiReport(fixture(
    { forbidden: [forbid('x_audit'), forbid('x-audit')] },
    [route('chatty', [header('x_audit', 'a'), header('x-audit', 'b')])],
  ))

  // The pointers follow capture order, not policy order, because a finding is
  // anchored where the evidence is.
  assert.deepEqual(
    findingsFor(report, 'forbidden-header-present').map((finding) => finding.location.pointer),
    ['/routes/0/headers/0', '/routes/0/headers/1'],
  )
})

test('the real binary emits the same order as the API, byte for byte', async () => {
  const files = fixture(
    { required: [requirement('x_audit'), requirement('x-audit')] },
    [route('a-route', []), route('Z-route', [])],
  )

  const fromApi = await apiReport(files)
  const { report: fromCli } = await cliReport(files)
  assert.deepEqual(fromCli, fromApi)
  assert.deepEqual(fromCli.routes.map((row) => row.id), ['Z-route', 'a-route'])
})

test('running twice over a root whose files were written in a different order changes nothing', async () => {
  const policy = { schemaVersion: '1', required: [{ header: 'x-audit' }, { header: 'x_audit' }] }
  const capture = { schemaVersion: '1', routes: [{ id: 'Z-route', headers: [] }, { id: 'a-route', headers: [] }] }

  const first = await withRoot({ 'policy.json': policy, 'capture.json': capture }, (root) => auditHeaders({ root }))
  const second = await withRoot({ 'capture.json': capture, 'policy.json': policy }, (root) => auditHeaders({ root }))

  assert.equal(JSON.stringify(first), JSON.stringify(second))
})
