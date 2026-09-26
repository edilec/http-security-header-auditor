/**
 * Route exceptions: the one construct that turns a failure into a pass.
 *
 * The guarantees pinned here are the ones that keep a waiver reviewable. A
 * waiver needs a reason and a date. It is compared against a date the caller
 * injects, never against a clock. It excuses a verdict about a response and
 * never a gap in the evidence -- which is the boundary that stops "we do not
 * know what this route carries" from being waived into a green build.
 */

import assert from 'node:assert/strict'
import test from 'node:test'

import {
  AS_OF,
  apiReport,
  cliReport,
  exception,
  findingsFor,
  fixture,
  header,
  raisedRules,
  requirement,
  route,
  routeRow,
} from './support.mjs'

const REQUIRE_XCTO = { required: [requirement('x-content-type-options', { allowedValues: ['nosniff'] })] }
const BARE_ROUTE = [route('bare', [])]

test('a live waiver excuses the finding and records what it excused', async () => {
  const report = await apiReport(fixture(
    { ...REQUIRE_XCTO, exceptions: [exception('bare', 'x-content-type-options', 'Static asset host, migration scheduled.', '2026-09-30')] },
    BARE_ROUTE,
  ), { asOf: AS_OF })

  assert.equal(report.status, 'pass')
  assert.equal(report.summary.errors, 0)
  assert.equal(report.summary.exceptionsApplied, 1)
  assert.deepEqual(raisedRules(report), ['exception-applied'])
  const [finding] = findingsFor(report, 'exception-applied')
  assert.equal(finding.message.includes('required-header-missing'), true)
  assert.equal(finding.evidence, 'Static asset host, migration scheduled.')
  assert.equal(routeRow(report, 'bare').verdict, 'waived')
  assert.deepEqual(routeRow(report, 'bare').waived, ['x-content-type-options'])
})

test('a waiver that expired before the as-of date excuses nothing and is reported', async () => {
  const report = await apiReport(fixture(
    { ...REQUIRE_XCTO, exceptions: [exception('bare', 'x-content-type-options', 'Migration was scheduled for 2024.', '2025-01-31')] },
    BARE_ROUTE,
  ), { asOf: AS_OF })

  assert.equal(report.status, 'fail')
  assert.equal(report.summary.exceptionsExpired, 1)
  assert.equal(report.summary.exceptionsApplied, 0)
  assert.deepEqual(raisedRules(report), ['exception-expired', 'required-header-missing'])
})

test('a waiver expiring on the as-of date still holds; the day after is too late', async () => {
  const build = (expires) => fixture(
    { ...REQUIRE_XCTO, exceptions: [exception('bare', 'x-content-type-options', 'Boundary case.', expires)] },
    BARE_ROUTE,
  )

  assert.equal((await apiReport(build('2026-03-01'), { asOf: '2026-03-01' })).status, 'pass')
  assert.equal((await apiReport(build('2026-02-28'), { asOf: '2026-03-01' })).status, 'fail')
})

/**
 * The expiry is compared against an injected date, and against nothing else.
 *
 * Without one, no expiry can be decided. The waiver is withheld -- which is the
 * direction that cannot turn an unknown into a pass -- and the run is
 * incomplete, so the exit code is 2 rather than 1.
 */
test('with no as-of date, no waiver is applied and the run is incomplete', async () => {
  const { code, report } = await cliReport(fixture(
    { ...REQUIRE_XCTO, exceptions: [exception('bare', 'x-content-type-options', 'Perfectly good reason.', '2099-12-31')] },
    BARE_ROUTE,
  ))

  assert.equal(report.status, 'incomplete')
  assert.equal(code, 2)
  assert.equal(report.asOf, null)
  assert.equal(report.summary.exceptionsApplied, 0)
  assert.deepEqual(raisedRules(report), ['exception-expiry-undecidable', 'required-header-missing'])
})

test('a waiver with no reason is refused, and excuses nothing', async () => {
  const report = await apiReport({
    'policy.json': { schemaVersion: '1', ...REQUIRE_XCTO, exceptions: [{ route: 'bare', header: 'x-content-type-options', expires: '2099-12-31' }] },
    'capture.json': { schemaVersion: '1', routes: BARE_ROUTE },
  }, { asOf: AS_OF })

  assert.equal(report.status, 'incomplete')
  assert.deepEqual(raisedRules(report), ['exception-reason-missing', 'required-header-missing'])
})

test('a waiver with no expiry is refused, and excuses nothing', async () => {
  const report = await apiReport({
    'policy.json': { schemaVersion: '1', ...REQUIRE_XCTO, exceptions: [{ route: 'bare', header: 'x-content-type-options', reason: 'Because.' }] },
    'capture.json': { schemaVersion: '1', routes: BARE_ROUTE },
  }, { asOf: AS_OF })

  assert.equal(report.status, 'incomplete')
  assert.deepEqual(raisedRules(report), ['exception-expiry-missing', 'required-header-missing'])
})

test('a waiver written as a pattern is refused rather than expanded', async () => {
  const report = await apiReport({
    'policy.json': {
      schemaVersion: '1',
      ...REQUIRE_XCTO,
      exceptions: [{ route: 'bare*', header: 'x-content-type-options', reason: 'Everything under bare.', expires: '2099-12-31' }],
    },
    'capture.json': { schemaVersion: '1', routes: BARE_ROUTE },
  }, { asOf: AS_OF })

  assert.equal(report.status, 'incomplete')
  assert.deepEqual(raisedRules(report), ['pattern-unsupported', 'required-header-missing'])
})

test('a waiver applies to the route it names and to no other', async () => {
  const report = await apiReport(fixture(
    { ...REQUIRE_XCTO, exceptions: [exception('bare', 'x-content-type-options', 'Only this one.', '2099-12-31')] },
    [route('bare', []), route('also-bare', [])],
  ), { asOf: AS_OF })

  assert.equal(report.status, 'fail')
  assert.equal(report.summary.errors, 1)
  assert.equal(routeRow(report, 'bare').verdict, 'waived')
  assert.equal(routeRow(report, 'also-bare').verdict, 'fail')
})

test('a waiver applies to the field it names and to no other', async () => {
  const report = await apiReport(fixture(
    {
      required: [requirement('x-content-type-options'), requirement('referrer-policy')],
      exceptions: [exception('bare', 'x-content-type-options', 'Only this field.', '2099-12-31')],
    },
    BARE_ROUTE,
  ), { asOf: AS_OF })

  assert.equal(report.status, 'fail')
  assert.deepEqual(findingsFor(report, 'required-header-missing').length, 1)
  assert.equal(findingsFor(report, 'required-header-missing')[0].message.includes('referrer-policy'), true)
})

test('a waiver for a route the capture does not contain is reported as covering nothing', async () => {
  const report = await apiReport(fixture(
    { required: [requirement('x-content-type-options')], exceptions: [exception('renamed', 'x-content-type-options', 'Route was renamed.', '2099-12-31')] },
    [route('ok', [header('X-Content-Type-Options', 'nosniff')])],
  ), { asOf: AS_OF })

  assert.equal(report.status, 'pass', 'a stale waiver is a warning, not a failure')
  assert.deepEqual(raisedRules(report), ['exception-route-unknown'])
})

test('a waiver that excused nothing on a route that does exist is reported too', async () => {
  const report = await apiReport(fixture(
    { required: [requirement('x-content-type-options')], exceptions: [exception('ok', 'x-content-type-options', 'No longer needed.', '2099-12-31')] },
    [route('ok', [header('X-Content-Type-Options', 'nosniff')])],
  ), { asOf: AS_OF })

  assert.equal(report.status, 'pass')
  assert.deepEqual(raisedRules(report), ['exception-unused'])
})

/**
 * The boundary that matters most.
 *
 * A field captured twice has no single value, so nothing about it was decided.
 * A waiver saying "we accept whatever this field says" is not reviewable,
 * because nobody knows what it says. Both cases below carry a waiver that names
 * exactly that route and field, and both still exit 2.
 */
test('a waiver cannot excuse a field that was captured twice', async () => {
  const { code, report } = await cliReport(fixture(
    {
      required: [requirement('content-security-policy')],
      exceptions: [exception('twice', 'content-security-policy', 'We accept this route as it is.', '2099-12-31')],
    },
    [route('twice', [
      header('Content-Security-Policy', "default-src 'self'"),
      header('content-security-policy', 'default-src *'),
    ])],
  ), ['--as-of', AS_OF])

  assert.equal(report.status, 'incomplete')
  assert.equal(code, 2)
  assert.equal(report.summary.exceptionsApplied, 0)
  assert.equal(raisedRules(report).includes('header-duplicated'), true)
  assert.equal(routeRow(report, 'twice').verdict, 'undecided')
  assert.deepEqual(routeRow(report, 'twice').undecided, ['content-security-policy'])
})

test('a waiver cannot excuse a Strict-Transport-Security field with no single reading', async () => {
  // RFC 6797 section 6.1 allows each directive once and tells a browser to
  // ignore a field that breaks that rule, so a conforming browser has no HSTS
  // policy here at all while a lenient one honours max-age=31536000. This build
  // does not pick, and a waiver saying "we accept this route as it is" cannot
  // make an unanswered question answered.
  const { code, report } = await cliReport(fixture(
    {
      required: [requirement('strict-transport-security', { minMaxAge: 31536000 })],
      exceptions: [exception('twice', 'strict-transport-security', 'We accept this route as it is.', '2099-12-31')],
    },
    [route('twice', [header('Strict-Transport-Security', 'max-age=31536000; max-age=0')])],
  ), ['--as-of', AS_OF])

  assert.equal(report.status, 'incomplete')
  assert.equal(code, 2)
  assert.equal(report.summary.exceptionsApplied, 0)
  assert.equal(raisedRules(report).includes('hsts-directive-duplicate'), true)
  assert.equal(routeRow(report, 'twice').verdict, 'undecided')
  assert.deepEqual(routeRow(report, 'twice').undecided, ['strict-transport-security'])
})

test('a Strict-Transport-Security field with one of each directive still passes', async () => {
  // The other half: refusing every HSTS field would be a different defect.
  const { code, report } = await cliReport(fixture(
    { required: [requirement('strict-transport-security', { minMaxAge: 31536000, requireIncludeSubDomains: true })] },
    [route('once', [header('Strict-Transport-Security', 'max-age=31536000; includeSubDomains')])],
  ), ['--as-of', AS_OF])

  assert.equal(report.status, 'pass')
  assert.equal(code, 0)
  assert.deepEqual(routeRow(report, 'once').undecided, [])
})

test('a waiver cannot excuse a value this build refused to parse', async () => {
  const { code, report } = await cliReport(fixture(
    {
      required: [requirement('content-security-policy')],
      exceptions: [exception('long', 'content-security-policy', 'We accept this route as it is.', '2099-12-31')],
    },
    [route('long', [header('Content-Security-Policy', `default-src ${'a'.repeat(200)}`)])],
  ), ['--as-of', AS_OF, '--max-header-value-length', '50'])

  assert.equal(report.status, 'incomplete')
  assert.equal(code, 2)
  assert.equal(report.summary.exceptionsApplied, 0)
  assert.equal(raisedRules(report).includes('header-value-too-long'), true)
})

test('the same route and field cannot be waived twice', async () => {
  const report = await apiReport(fixture(
    {
      ...REQUIRE_XCTO,
      exceptions: [
        exception('bare', 'x-content-type-options', 'First reason.', '2026-04-01'),
        exception('bare', 'X-Content-Type-Options', 'Second, later reason.', '2099-12-31'),
      ],
    },
    BARE_ROUTE,
  ), { asOf: AS_OF })

  assert.equal(report.status, 'incomplete', 'a refused waiver leaves part of the policy unread')
  assert.equal(raisedRules(report).includes('policy-invalid'), true)
})

test('a waiver can excuse a forbidden field, which is a verdict like any other', async () => {
  const report = await apiReport(fixture(
    {
      forbidden: [{ header: 'server' }],
      exceptions: [exception('proxy', 'server', 'Shared edge proxy; removal tracked in PLAT-421.', '2099-12-31')],
    },
    [route('proxy', [header('Server', 'nginx')])],
  ), { asOf: AS_OF })

  assert.equal(report.status, 'pass')
  assert.deepEqual(raisedRules(report), ['exception-applied'])
})
