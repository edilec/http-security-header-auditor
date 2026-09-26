import assert from 'node:assert/strict'
import test from 'node:test'

import {
  CAPTURE_DOCUMENT_KEYS,
  EXCEPTION_KEYS,
  FORBIDDEN_KEYS,
  HEADER_KEYS,
  POLICY_DOCUMENT_KEYS,
  REQUIREMENT_KEYS,
  ROUTE_KEYS,
} from '../src/index.mjs'
import { apiReport, findingsFor, fixture, header, raisedRules, requirement, route } from './support.mjs'

const REQUIRE_XCTO = { required: [requirement('x-content-type-options')] }
const OK_ROUTE = [route('ok', [header('X-Content-Type-Options', 'nosniff')])]

const withPolicy = (policy) => ({
  'policy.json': policy,
  'capture.json': { schemaVersion: '1', routes: OK_ROUTE },
})
const withCapture = (capture) => ({
  'policy.json': { schemaVersion: '1', ...REQUIRE_XCTO },
  'capture.json': capture,
})

test('the documented key lists are the ones the compilers enforce, in order', () => {
  for (const list of [CAPTURE_DOCUMENT_KEYS, POLICY_DOCUMENT_KEYS, ROUTE_KEYS, HEADER_KEYS, REQUIREMENT_KEYS, FORBIDDEN_KEYS, EXCEPTION_KEYS]) {
    assert.deepEqual(list, [...list].sort(), 'key lists are listed in code-unit order')
    assert.equal(new Set(list).size, list.length)
  }
})

test('an unknown document key is refused rather than ignored, so a typo cannot disable a check', async () => {
  const report = await apiReport(withPolicy({ schemaVersion: '1', requiredd: [requirement('x-content-type-options')] }))

  assert.equal(report.status, 'incomplete')
  assert.deepEqual(raisedRules(report), ['document-invalid'])
  assert.equal(findingsFor(report, 'document-invalid')[0].message.includes('requiredd'), true)
  assert.equal(report.summary.checked, 0, 'a policy nobody could read audits nothing')
})

test('an unknown requirement key is refused, and the requirement is not silently half-applied', async () => {
  const report = await apiReport(withPolicy({
    schemaVersion: '1',
    required: [{ header: 'x-content-type-options', allowedValue: ['nosniff'] }],
  }))

  assert.equal(report.status, 'incomplete')
  assert.equal(raisedRules(report).includes('policy-invalid'), true)
})

test('an option declared on a field this build does not read it on is refused', async () => {
  const report = await apiReport(withPolicy({
    schemaVersion: '1',
    required: [{ header: 'x-frame-options', minMaxAge: 600 }],
  }))

  assert.equal(report.status, 'incomplete')
  const [finding] = findingsFor(report, 'policy-invalid')
  assert.equal(finding.message.includes('minMaxAge'), true)
  assert.equal(finding.message.includes('strict-transport-security'), true)
})

test('a directive option on a field that is not the policy field is refused too', async () => {
  const report = await apiReport(withPolicy({
    schemaVersion: '1',
    required: [{ header: 'content-security-policy-report-only', requiredDirectives: ['default-src'] }],
  }))

  assert.equal(report.status, 'incomplete')
  assert.equal(findingsFor(report, 'policy-invalid')[0].message.includes('requiredDirectives'), true)
})

test('a field that is both required and forbidden is a contradiction inside the policy', async () => {
  const report = await apiReport(withPolicy({
    schemaVersion: '1',
    required: [requirement('x-content-type-options')],
    forbidden: [{ header: 'X-Content-Type-Options' }],
  }))

  assert.equal(report.status, 'incomplete')
  assert.equal(raisedRules(report).includes('policy-contradiction'), true)
  assert.equal(report.summary.requirements, 0, 'neither entry is evaluated against any route')
  assert.equal(report.summary.forbidden, 0)
})

test('a schemaVersion this build does not implement is unsupported, not ignored', async () => {
  const report = await apiReport(withCapture({ schemaVersion: '2', routes: OK_ROUTE }))

  assert.equal(report.status, 'incomplete')
  assert.equal(raisedRules(report).includes('schema-version-unsupported'), true)
})

test('a route id written as a pattern is refused rather than matched against anything', async () => {
  const report = await apiReport(withCapture({ schemaVersion: '1', routes: [{ id: '/api/*', headers: [] }] }))

  assert.equal(report.status, 'incomplete')
  assert.equal(raisedRules(report).includes('pattern-unsupported'), true)
  assert.equal(report.summary.routes, 0)
})

test('a route id outside the identifier alphabet is refused without echoing it', async () => {
  const report = await apiReport(withCapture({ schemaVersion: '1', routes: [{ id: 'has space', headers: [] }] }))

  const [finding] = findingsFor(report, 'identifier-invalid')
  assert.equal(finding.message.includes('has space'), false, 'a refused value is described, never reproduced')
  assert.equal(finding.message.includes('a string of 9 character(s)'), true)
})

test('a duplicate route id refuses the second copy rather than choosing between them', async () => {
  const report = await apiReport(withCapture({
    schemaVersion: '1',
    routes: [route('same', [header('X-Content-Type-Options', 'nosniff')]), route('same', [])],
  }))

  assert.equal(report.status, 'incomplete')
  assert.equal(raisedRules(report).includes('route-duplicate'), true)
  assert.equal(report.summary.routes, 1)
})

test('a field entry that is not readable is counted, not dropped', async () => {
  const report = await apiReport(withCapture({
    schemaVersion: '1',
    routes: [{ id: 'ok', headers: [{ name: 'X-Content-Type-Options', value: 'nosniff' }, { name: 'x bad', value: 'v' }] }],
  }))

  assert.equal(report.status, 'incomplete', 'a field nobody could read leaves the route undecided')
  assert.equal(raisedRules(report).includes('header-invalid'), true)
})

test('a field value that is not a string is refused without describing its contents', async () => {
  const report = await apiReport(withCapture({
    schemaVersion: '1',
    routes: [{ id: 'ok', headers: [{ name: 'X-Content-Type-Options', value: 1 }] }],
  }))

  const [finding] = findingsFor(report, 'header-invalid')
  assert.equal(finding.message.includes('must be a string'), true)
  assert.equal(finding.message.includes('an integer'), true)
})

test('a field value carrying a control character is refused unparsed and never reproduced', async () => {
  const injected = `nosniff${String.fromCharCode(0x0d, 0x0a)}Set-Cookie: a=b`
  const report = await apiReport(withCapture({
    schemaVersion: '1',
    routes: [{ id: 'injected', headers: [{ name: 'X-Content-Type-Options', value: injected }] }],
  }))

  assert.equal(report.status, 'incomplete')
  assert.equal(raisedRules(report).includes('header-value-control-character'), true)
  assert.equal(JSON.stringify(report).includes('Set-Cookie'), false)
})

test('a capture with no routes array at all says so rather than auditing nothing quietly', async () => {
  const report = await apiReport(withCapture({ schemaVersion: '1' }))

  assert.equal(report.status, 'incomplete')
  assert.equal(findingsFor(report, 'document-invalid')[0].message.includes('routes'), true)
})

test('an empty capture and an empty policy are both legal and both refuse to be green', async () => {
  const report = await apiReport({
    'policy.json': { schemaVersion: '1', required: [], forbidden: [], exceptions: [] },
    'capture.json': { schemaVersion: '1', routes: [] },
  })

  assert.equal(report.status, 'incomplete')
  assert.equal(report.summary.checked, 0)
  assert.deepEqual(raisedRules(report), ['no-checks-performed'])
})

test('a policy document that is not an object at all is described, not parsed', async () => {
  const report = await apiReport(withPolicy(['not', 'a', 'policy']))

  assert.equal(report.status, 'incomplete')
  assert.equal(findingsFor(report, 'document-invalid')[0].message.includes('an array of 3 item(s)'), true)
})

test('bytes that are not JSON, and bytes that are not UTF-8, are each named for what they are', async () => {
  const notJson = await apiReport({
    'policy.json': '{ this is not json',
    'capture.json': { schemaVersion: '1', routes: OK_ROUTE },
  })
  assert.equal(notJson.status, 'incomplete')
  assert.equal(raisedRules(notJson).includes('input-not-json'), true)

  const notUtf8 = await apiReport({
    'policy.json': new Uint8Array([0x7b, 0xff, 0xfe, 0x7d]),
    'capture.json': { schemaVersion: '1', routes: OK_ROUTE },
  })
  assert.equal(notUtf8.status, 'incomplete')
  assert.equal(raisedRules(notUtf8).includes('input-not-utf8'), true)
})

test('a missing input is incomplete evidence and carries a report saying which file', async () => {
  const report = await apiReport({ 'capture.json': { schemaVersion: '1', routes: OK_ROUTE } })

  assert.equal(report.status, 'incomplete')
  const [finding] = findingsFor(report, 'input-unreadable')
  assert.equal(finding.location.file, 'policy.json')
})

test('the policy is decoded as strictly as the capture, with no exception for configuration', async () => {
  const report = await apiReport({
    'policy.json': new Uint8Array([0xc3]),
    'capture.json': { schemaVersion: '1', routes: OK_ROUTE },
  })

  assert.equal(raisedRules(report).includes('input-not-utf8'), true)
  assert.equal(findingsFor(report, 'input-not-utf8')[0].location.file, 'policy.json')
})

test('a capture whose routes compile is audited even when one route did not', async () => {
  const report = await apiReport(withCapture({
    schemaVersion: '1',
    routes: [route('good', [header('X-Content-Type-Options', 'nosniff')]), { id: 'bad', headers: 'not an array' }],
  }))

  assert.equal(report.status, 'incomplete', 'a route nobody compiled was not audited')
  assert.equal(report.summary.routes, 1)
  assert.equal(report.summary.evaluated, 1)
  assert.equal(raisedRules(report).includes('route-invalid'), true)
})

test('the same field required twice refuses the second entry rather than picking one', async () => {
  const report = await apiReport(withPolicy({
    schemaVersion: '1',
    required: [requirement('x-content-type-options', { allowedValues: ['nosniff'] }), requirement('X-Content-Type-Options', { allowedValues: ['deny'] })],
  }))

  assert.equal(report.status, 'incomplete')
  assert.equal(findingsFor(report, 'policy-invalid')[0].message.includes('required twice'), true)
})

test('a label is optional metadata and never affects a verdict', async () => {
  const labelled = await apiReport({
    'policy.json': { schemaVersion: '1', label: 'baseline', ...REQUIRE_XCTO },
    'capture.json': { schemaVersion: '1', label: 'staging', routes: OK_ROUTE },
  })

  assert.equal(labelled.status, 'pass')
  assert.deepEqual(labelled.findings, [])
})

test('an allowed value carrying a control character is refused at policy compile time', async () => {
  const report = await apiReport(withPolicy({
    schemaVersion: '1',
    required: [{ header: 'x-content-type-options', allowedValues: [`nosniff${String.fromCharCode(0x202e)}`] }],
  }))

  assert.equal(report.status, 'incomplete')
  assert.equal(raisedRules(report).includes('policy-invalid'), true)
})

test('a forbidden source that is really a whole directive is refused', async () => {
  const report = await apiReport(withPolicy({
    schemaVersion: '1',
    required: [{ header: 'content-security-policy', forbiddenSources: ["script-src 'unsafe-inline'"] }],
  }))

  assert.equal(report.status, 'incomplete')
  assert.equal(findingsFor(report, 'policy-invalid')[0].message.includes('no space or semicolon'), true)
})
