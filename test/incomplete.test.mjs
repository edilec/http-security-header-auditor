/**
 * `incomplete`, and the flags that are the only thing keeping a run out of
 * `pass`.
 *
 * Deleting one `incomplete = true` once let an entirely unread input report
 * `pass` in this catalog, with the full suite still green, because the finding
 * beside it happened to be `error` severity and the status came out `fail`
 * anyway. Every case below therefore asserts `status: "incomplete"` and exit 2
 * specifically -- not merely "not a pass" -- so that a flag whose removal would
 * leave `fail` in its place is still caught.
 *
 * The distinction matters to a consumer. `fail` says the capture was audited and
 * did not satisfy the policy; `incomplete` says the audit did not finish, and no
 * claim about the capture should be read out of it.
 */

import assert from 'node:assert/strict'
import test from 'node:test'

import { exitCodeFor } from '../src/index.mjs'
import { apiReport, cliReport, clean, header, raisedRules, requirement, route, routeRow } from './support.mjs'

const REQUIRE_XCTO = { required: [requirement('x-content-type-options')] }
const OK = route('ok', [header('X-Content-Type-Options', 'nosniff')])

async function bothWays(files, extraArgs = [], options = {}) {
  const fromApi = await apiReport(files, options)
  const { code, report } = await cliReport(files, extraArgs)
  assert.deepEqual(report, fromApi, 'the API and the binary must agree')
  return { code, report }
}

test('the clean fixture is a pass and exits 0, so every case below is a real change', async () => {
  const { code, report } = await bothWays(clean())

  assert.equal(report.status, 'pass')
  assert.equal(code, 0)
  assert.equal(exitCodeFor(report), 0)
})

test('an unread input is incomplete, never a pass and never merely a failure', async () => {
  const { code, report } = await bothWays({ 'policy.json': { schemaVersion: '1', ...REQUIRE_XCTO } })

  assert.equal(report.status, 'incomplete')
  assert.equal(code, 2)
  assert.equal(report.summary.checked, 0)
})

test('a field captured twice is incomplete, because nothing about it was decided', async () => {
  const { code, report } = await bothWays({
    'policy.json': { schemaVersion: '1', ...REQUIRE_XCTO },
    'capture.json': { schemaVersion: '1', routes: [route('twice', [header('X-Content-Type-Options', 'nosniff'), header('x-content-type-options', 'sniff')]), OK] },
  })

  assert.equal(report.status, 'incomplete')
  assert.equal(code, 2)
  assert.equal(routeRow(report, 'twice').verdict, 'undecided')
  assert.equal(report.summary.undecided, 1)
})

test('a value refused unparsed is incomplete, even though the field is present', async () => {
  const { code, report } = await bothWays({
    'policy.json': { schemaVersion: '1', ...REQUIRE_XCTO },
    'capture.json': { schemaVersion: '1', routes: [route('long', [header('X-Content-Type-Options', 'n'.repeat(40))]), OK] },
  }, ['--max-header-value-length', '10'], { limits: { maxHeaderValueLength: 10 } })

  assert.equal(report.status, 'incomplete')
  assert.equal(code, 2)
  assert.deepEqual(routeRow(report, 'long').undecided, ['x-content-type-options'])
})

test('a route that did not compile is incomplete, and its absence is counted', async () => {
  const { code, report } = await bothWays({
    'policy.json': { schemaVersion: '1', ...REQUIRE_XCTO },
    'capture.json': { schemaVersion: '1', routes: [{ id: 'broken', headers: 'not an array' }, OK] },
  })

  assert.equal(report.status, 'incomplete')
  assert.equal(code, 2)
  assert.equal(report.summary.routes, 1, 'only the route that compiled is counted as a route')
  assert.equal(report.routes.length, 1)
})

test('a policy entry that did not compile is incomplete', async () => {
  const { code, report } = await bothWays({
    'policy.json': { schemaVersion: '1', required: [{ header: 'x-content-type-options' }, { header: 'referrer-policy', bogus: true }] },
    'capture.json': { schemaVersion: '1', routes: [OK] },
  })

  assert.equal(report.status, 'incomplete')
  assert.equal(code, 2)
  assert.equal(report.summary.requirements, 1)
})

/**
 * The vacuous pass, refused explicitly.
 *
 * Two documents that both compile with nothing to compare would otherwise be
 * `pass` with `checked: 0` -- green on no evidence at all. Both halves of the
 * guard are asserted: the finding, and the flag. Removing either one changes the
 * observable result, so neither can be deleted quietly.
 */
test('two empty documents refuse to be green, with a finding that says why', async () => {
  const { code, report } = await bothWays({
    'policy.json': { schemaVersion: '1', required: [], forbidden: [], exceptions: [] },
    'capture.json': { schemaVersion: '1', routes: [] },
  })

  assert.equal(report.status, 'incomplete')
  assert.equal(code, 2)
  assert.equal(report.summary.checked, 0)
  assert.deepEqual(raisedRules(report), ['no-checks-performed'])
})

test('a policy with rules and a capture with no routes is vacuous too', async () => {
  const { report } = await bothWays({
    'policy.json': { schemaVersion: '1', ...REQUIRE_XCTO },
    'capture.json': { schemaVersion: '1', routes: [] },
  })

  assert.equal(report.status, 'incomplete')
  assert.equal(report.summary.checked, 0)
  assert.deepEqual(raisedRules(report), ['no-checks-performed'])
})

test('a capture with routes and a policy with no rules is vacuous too', async () => {
  const { report } = await bothWays({
    'policy.json': { schemaVersion: '1', required: [], forbidden: [] },
    'capture.json': { schemaVersion: '1', routes: [OK] },
  })

  assert.equal(report.status, 'incomplete')
  assert.equal(report.summary.checked, 0)
  assert.deepEqual(raisedRules(report), ['no-checks-performed'])
})

test('one decided pair is enough to be green, which is what makes the guard a guard', async () => {
  const { code, report } = await bothWays({
    'policy.json': { schemaVersion: '1', ...REQUIRE_XCTO },
    'capture.json': { schemaVersion: '1', routes: [OK] },
  })

  assert.equal(report.status, 'pass')
  assert.equal(code, 0)
  assert.equal(report.summary.checked, 1)
})

test('an undecided pair is never counted as a decided one', async () => {
  const report = await apiReport({
    'policy.json': { schemaVersion: '1', ...REQUIRE_XCTO },
    'capture.json': { schemaVersion: '1', routes: [route('twice', [header('X-Content-Type-Options', 'a'), header('X-Content-Type-Options', 'b')])] },
  })

  assert.equal(report.summary.checked, 0)
  assert.equal(report.summary.undecided, 1)
  assert.equal(report.status, 'incomplete')
  // Both guards fire here, which is correct: the pair was undecided *and* the
  // run decided nothing at all.
  assert.equal(raisedRules(report).includes('no-checks-performed'), true)
})

test('a waiver whose expiry could not be decided is incomplete, not a pass and not a failure alone', async () => {
  const { code, report } = await cliReport({
    'policy.json': {
      schemaVersion: '1',
      ...REQUIRE_XCTO,
      exceptions: [{ route: 'bare', header: 'x-content-type-options', reason: 'Perfectly good reason.', expires: '2099-12-31' }],
    },
    'capture.json': { schemaVersion: '1', routes: [route('bare', [])] },
  })

  assert.equal(report.status, 'incomplete')
  assert.equal(code, 2)
  assert.equal(report.asOf, null)
})

test('the same run with a date is a decided failure rather than an incomplete one', async () => {
  const { code, report } = await cliReport({
    'policy.json': {
      schemaVersion: '1',
      ...REQUIRE_XCTO,
      exceptions: [{ route: 'bare', header: 'x-content-type-options', reason: 'Perfectly good reason.', expires: '2099-12-31' }],
    },
    'capture.json': { schemaVersion: '1', routes: [route('bare', [])] },
  }, ['--as-of', '2026-03-01'])

  assert.equal(report.status, 'pass')
  assert.equal(code, 0)
})

test('exitCodeFor maps the three statuses and nothing else', () => {
  assert.equal(exitCodeFor({ status: 'pass' }), 0)
  assert.equal(exitCodeFor({ status: 'fail' }), 1)
  assert.equal(exitCodeFor({ status: 'incomplete' }), 2)
})

test('a report that is incomplete says so on stderr as well as in its status', async () => {
  const { stderr } = await cliReport({
    'policy.json': { schemaVersion: '1', ...REQUIRE_XCTO },
    'capture.json': { schemaVersion: '1', routes: [] },
  })

  assert.equal(stderr.includes('incomplete:'), true)
  assert.equal(stderr.includes('this run is not a pass'), true)
})
