/**
 * Every documented limit, enforced and observed.
 *
 * A limit that is accepted and never applied is worse than no limit: it reads
 * like a bound in the help text while nothing bounds anything. Each case below
 * drives a real input past a real limit and asserts that the run says so and
 * refuses to be green -- never that it quietly read a prefix.
 */

import assert from 'node:assert/strict'
import test from 'node:test'

import { DEFAULT_LIMITS, HARD_LIMITS, MAX_FIELD_CHECKS, auditHeaders, validateLimits } from '../src/index.mjs'
import {
  AS_OF,
  apiReport,
  cliReport,
  cliRun,
  cliRunBoundedHeap,
  clean,
  exception,
  findingsFor,
  fixture,
  header,
  raisedRules,
  requirement,
  route,
  withRoot,
} from './support.mjs'

const REQUIRE_CSP = { required: [requirement('content-security-policy')] }

test('the two limit tables name exactly the same limits, and no default exceeds its cap', () => {
  assert.deepEqual(Object.keys(DEFAULT_LIMITS).sort(), Object.keys(HARD_LIMITS).sort())
  for (const [name, value] of Object.entries(DEFAULT_LIMITS)) {
    assert.equal(Number.isInteger(value) && value >= 1, true, `${name} must be a positive integer`)
    assert.equal(value <= HARD_LIMITS[name], true, `${name} default must not exceed its cap`)
  }
})

test('an unknown limit key throws rather than being ignored', () => {
  assert.throws(() => validateLimits({ maxRoute: 5 }), /Unknown limit "maxRoute"/)
  assert.throws(() => validateLimits({ maxRoutes: 0 }), /between 1 and/)
  assert.throws(() => validateLimits({ maxRoutes: HARD_LIMITS.maxRoutes + 1 }), /between 1 and/)
  assert.throws(() => validateLimits({ maxRoutes: 1.5 }), /between 1 and/)
  assert.throws(() => validateLimits([]), /limits must be an object/)
})

test('an unknown option throws, so a mistyped call never audits something else quietly', async () => {
  await assert.rejects(() => auditHeaders({ root: '.', asof: '2026-03-01' }), /Unknown option "asof"/)
  await assert.rejects(() => auditHeaders({ root: '.', asOf: 'tomorrow' }), /asOf must be a calendar date/)
  await assert.rejects(() => auditHeaders({ root: '.', clock: 5 }), /clock must be a function/)
  await assert.rejects(() => auditHeaders({}), /root must be a non-empty string/)
})

test('more routes than maxRoutes compiles nothing rather than a prefix', async () => {
  const routes = Array.from({ length: 4 }, (_, index) => route(`r${index}`, [header('X-Content-Type-Options', 'nosniff')]))
  const report = await apiReport(fixture({ required: [requirement('x-content-type-options')] }, routes), { limits: { maxRoutes: 3 } })

  assert.equal(report.status, 'incomplete')
  assert.equal(report.summary.routes, 0)
  assert.equal(findingsFor(report, 'too-many-routes')[0].message.includes('maxRoutes limit of 3'), true)
})

test('more fields than maxHeadersPerRoute refuses the route rather than reading part of it', async () => {
  const headers = Array.from({ length: 4 }, (_, index) => header(`x-${index}`, 'v'))
  const report = await apiReport(fixture(REQUIRE_CSP, [route('fat', headers)]), { limits: { maxHeadersPerRoute: 3 } })

  assert.equal(report.status, 'incomplete')
  assert.equal(report.summary.routes, 0)
  assert.equal(raisedRules(report).includes('too-many-headers'), true)
})

test('a value longer than maxHeaderValueLength is never parsed, and the field stays undecided', async () => {
  const report = await apiReport(fixture(REQUIRE_CSP, [
    route('long', [header('Content-Security-Policy', `default-src ${'a'.repeat(200)}`)]),
  ]), { limits: { maxHeaderValueLength: 64 } })

  assert.equal(report.status, 'incomplete')
  assert.deepEqual(report.routes[0].undecided, ['content-security-policy'])
  assert.equal(report.routes[0].csp.analysed, false)
  assert.equal(findingsFor(report, 'header-value-too-long')[0].message.includes('maxHeaderValueLength limit of 64'), true)
})

test('a value at exactly the limit is read; one character more is refused', async () => {
  const build = (length) => fixture(
    { required: [requirement('x-content-type-options', { allowedValues: ['nosniff'] })] },
    [route('edge', [header('X-Content-Type-Options', 'nosniff'.padEnd(length, ' '))])],
  )

  assert.equal((await apiReport(build(32), { limits: { maxHeaderValueLength: 32 } })).status, 'pass')
  assert.equal((await apiReport(build(33), { limits: { maxHeaderValueLength: 32 } })).status, 'incomplete')
})

test('a policy string past maxCspDirectives is refused whole, not parsed in part', async () => {
  const policy = Array.from({ length: 5 }, (_, index) => `img-src${index} 'self'`).join('; ')
  const report = await apiReport(fixture(REQUIRE_CSP, [route('wide', [header('Content-Security-Policy', policy)])]), {
    limits: { maxCspDirectives: 4 },
  })

  assert.equal(report.status, 'incomplete')
  assert.deepEqual(report.routes[0].csp.directives, [])
  assert.equal(findingsFor(report, 'csp-unparseable')[0].message.includes('maxCspDirectives limit of 4'), true)
})

test('a directive past maxCspSources is refused whole too', async () => {
  const sources = Array.from({ length: 5 }, (_, index) => `https://h${index}.example.invalid`).join(' ')
  const report = await apiReport(fixture(REQUIRE_CSP, [route('deep', [header('Content-Security-Policy', `img-src ${sources}`)])]), {
    limits: { maxCspSources: 4 },
  })

  assert.equal(report.status, 'incomplete')
  assert.equal(findingsFor(report, 'csp-unparseable')[0].message.includes('maxCspSources limit of 4'), true)
})

test('a policy past maxRequirements compiles nothing', async () => {
  const required = Array.from({ length: 3 }, (_, index) => requirement(`x-${index}`))
  const report = await apiReport(fixture({ required, forbidden: [{ header: 'server' }] }, [route('any', [])]), {
    limits: { maxRequirements: 3 },
  })

  assert.equal(report.status, 'incomplete')
  assert.equal(report.summary.requirements, 0)
  assert.equal(raisedRules(report).includes('too-many-requirements'), true)
})

test('a policy past maxExceptions compiles nothing', async () => {
  const exceptions = Array.from({ length: 3 }, (_, index) => exception('any', `x-${index}`, 'Reason.', '2099-12-31'))
  const report = await apiReport(fixture({ required: [requirement('x-0')], exceptions }, [route('any', [])]), {
    limits: { maxExceptions: 2 },
  })

  assert.equal(report.status, 'incomplete')
  assert.equal(raisedRules(report).includes('too-many-exceptions'), true)
})

test('a document larger than maxFileBytes is not read at all', async () => {
  const report = await apiReport(clean(), { limits: { maxFileBytes: 10 } })

  assert.equal(report.status, 'incomplete')
  assert.equal(findingsFor(report, 'input-too-large').length, 2, 'both documents are reported, not just the first')
})

test('more findings than maxFindings is a partial report that says it is partial', async () => {
  const routes = Array.from({ length: 6 }, (_, index) => route(`r${index}`, []))
  const report = await apiReport(fixture({ required: [requirement('x-content-type-options')] }, routes), {
    limits: { maxFindings: 4 },
  })

  assert.equal(report.status, 'incomplete')
  assert.equal(report.findings.length, 4)
  assert.equal(findingsFor(report, 'too-many-findings')[0].message.includes('3 were not reported'), true)
})

/**
 * The size of a report is a product, and the product is bounded too.
 *
 * `maxRoutes` and `maxRequirements` each bound one dimension and each is
 * enforced. What neither of them bounds is the report, because every route row
 * lists the required fields that route was missing: the entries are
 * `maxRoutes x maxRequirements`, and at the published caps that is forty
 * million. A run at those caps built a report `JSON.stringify` refused --
 * `RangeError: Invalid string length` -- and exited with an empty stdout and an
 * exit code that says the capture was audited and failed.
 *
 * The product is therefore refused in `validateLimits`, before any evidence is
 * read: a configuration is not a subject, so refusing one claims nothing about
 * anything.
 */
test('two limits whose product this build cannot report are refused together', () => {
  assert.throws(
    () => validateLimits({ maxRoutes: HARD_LIMITS.maxRoutes, maxRequirements: HARD_LIMITS.maxRequirements }),
    /times limits.maxRequirements \(2000\) is 40000000 field check\(s\), above the 5000000/,
  )
  assert.equal(
    HARD_LIMITS.maxRoutes * HARD_LIMITS.maxRequirements > MAX_FIELD_CHECKS,
    true,
    'the caps still multiply past what one report can hold, so this bound still has a subject',
  )
})

test('the field-check bound is applied at the product, not one below it', () => {
  const routes = MAX_FIELD_CHECKS / 1000
  assert.equal(validateLimits({ maxRoutes: routes, maxRequirements: 1000 }).maxRoutes, routes)
  assert.throws(() => validateLimits({ maxRoutes: routes + 1, maxRequirements: 1000 }), /above the 5000000/)
  assert.equal(DEFAULT_LIMITS.maxRoutes * DEFAULT_LIMITS.maxRequirements <= MAX_FIELD_CHECKS, true)
})

test('the command line refuses that pair with an empty stdout and no report', async () => {
  const result = await withRoot(clean(), (root) => cliRun([
    '--root', root, '--json',
    '--max-routes', String(HARD_LIMITS.maxRoutes),
    '--max-requirements', String(HARD_LIMITS.maxRequirements),
  ]))

  assert.equal(result.code, 2)
  assert.equal(result.stdout, '', 'a configuration that never had a subject does not print a report')
  assert.match(result.stderr, /field check\(s\), above the/)
})

/**
 * `maxFindings` bounds the run, not just the printed array.
 *
 * It used to bound only the array: every row was accumulated, turned into a
 * finding object and sorted, and only then was the slice applied. So the bound
 * cost as much memory as having no bound at all, and at limits this package
 * publishes as legal the process died of heap exhaustion -- exit 134, empty
 * stdout, no finding naming any limit. `maxRuntimeMs` could not save it either:
 * the collapse is in report construction, after the loop the budget guards.
 *
 * A million findings against a five-finding budget is the shape, and a small
 * heap is what makes the difference observable: bounded on arrival it finishes
 * inside 96 MB, unbounded it dies with a gigabyte.
 */
test('a million findings against a five-finding budget runs in a small heap', async () => {
  const routes = Array.from({ length: 1000 }, (_, index) => route(`r${String(index).padStart(5, '0')}`, []))
  const required = Array.from({ length: 1000 }, (_, index) => requirement(`x-required-${String(index).padStart(4, '0')}`))

  const result = await withRoot(fixture({ required }, routes), (root) => cliRunBoundedHeap(256, [
    '--root', root, '--json', '--as-of', AS_OF,
    '--max-routes', '1000', '--max-requirements', '1000',
    '--max-findings', '5', '--max-runtime-ms', '600000',
  ]))

  assert.equal(result.code, 2, `the run did not finish: ${result.stderr.slice(0, 200)}`)
  assert.notEqual(result.stdout, '', 'the run printed no report at all')

  const report = JSON.parse(result.stdout)
  assert.equal(report.status, 'incomplete')
  assert.equal(report.findings.length, 5)
  assert.equal(report.summary.checked, 1000000)
  const truncation = findingsFor(report, 'too-many-findings')[0]
  assert.equal(truncation.message.includes('999996 were not reported'), true, truncation.message)
})

/**
 * The time budget, and the re-check that makes an aborted run honest.
 *
 * The clock is injected, so no case here waits. The budget is checked once per
 * route, which makes a route atomic: a row exists only for a route that was
 * evaluated from end to end. What downgrades the run is not the `catch` -- a
 * flag set where the failure is noticed backstops itself and no test could tell
 * it was gone -- but the comparison of rows against routes *after* the loop.
 */
test('a run that passes its budget mid-way keeps the rows it finished and downgrades the rest', async () => {
  let tick = 0
  const clock = () => {
    tick += 1
    return tick <= 2 ? 0 : 999999
  }

  const { report } = await runWithClock(clock)

  assert.equal(report.status, 'incomplete')
  assert.equal(report.summary.evaluated, 1)
  assert.equal(report.summary.unevaluated, 1)
  assert.equal(report.routes.length, 1, 'no row exists for the route the loop never reached')
  assert.equal(raisedRules(report).includes('time-budget-exceeded'), true)
})

test('a run that passes its budget before the first route evaluates nothing', async () => {
  let tick = 0
  const clock = () => {
    tick += 1
    return tick === 1 ? 0 : 999999
  }

  const { report } = await runWithClock(clock)

  assert.equal(report.status, 'incomplete')
  assert.equal(report.summary.evaluated, 0)
  assert.deepEqual(report.routes, [])
  assert.equal(report.summary.checked, 0)
})

test('a generous budget evaluates every route and says nothing about time', async () => {
  const { report } = await runWithClock(() => 0)

  assert.equal(report.status, 'pass')
  assert.equal(report.summary.evaluated, 2)
  assert.equal(raisedRules(report).includes('time-budget-exceeded'), false)
})

async function runWithClock(clock) {
  const report = await apiReport(fixture(
    { required: [requirement('x-content-type-options', { allowedValues: ['nosniff'] })] },
    [
      route('a', [header('X-Content-Type-Options', 'nosniff')]),
      route('b', [header('X-Content-Type-Options', 'nosniff')]),
    ],
  ), { clock, limits: { maxRuntimeMs: 1000 } })
  return { report }
}

test('the CLI wires every limit flag through, and refuses a value that is not a positive integer', async () => {
  const tooSmall = await cliReport(clean(), ['--max-file-bytes', '10'])
  assert.equal(tooSmall.code, 2)
  assert.equal(tooSmall.report.status, 'incomplete')

  const notANumber = await cliReport(clean(), ['--max-routes', 'lots'])
  assert.equal(notANumber.code, 2)
  assert.equal(notANumber.stdout, '', 'a configuration error leaves stdout empty')
  assert.equal(notANumber.stderr.includes('--max-routes requires a positive integer'), true)

  const unknown = await cliReport(clean(), ['--max-route', '5'])
  assert.equal(unknown.code, 2)
  assert.equal(unknown.stdout, '')
  assert.equal(unknown.stderr.includes('Unknown option'), true)
})

test('a flag carrying a value may be given once, so a repeat cannot silently win', async () => {
  const repeated = await cliReport(clean(), ['--as-of', '2020-01-01', '--as-of', '2030-01-01'])

  assert.equal(repeated.code, 2)
  assert.equal(repeated.stdout, '')
  assert.equal(repeated.stderr.includes('--as-of was given more than once'), true)
})
