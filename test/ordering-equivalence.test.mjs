/**
 * The six ordering sites that cannot be pinned, proved equivalent instead of
 * left as gaps.
 *
 * `test/ordering.test.mjs` pins fifteen of this package's twenty-one ordering
 * sites by emitting a sequence a collator would emit differently. The remaining
 * six order values drawn from alphabets on which code-unit order and English
 * collation agree on every pair:
 *
 * - CSP directive names, over `[a-z0-9-]` after case folding: the known
 *   catalog, the parsed directive list on a route row, and the unknown
 *   directives named in `csp-analysis-incomplete`.
 * - Rule ids, over `[a-z-]`: the finding sort key and the list of waived rules
 *   in `exception-applied`.
 *
 * The sixth site, the pointer component of the finding sort key, is *not* one
 * of them, and saying it was is the mistake this file used to make. JSON
 * Pointers are drawn from `[A-Za-z0-9/]`, which includes upper case, and
 * collation folds case before it compares: `/required/0/requiredDirectives/0`
 * sorts after `/required/0/requireIncludeSubDomains` by code unit and before it
 * under a collator. The old shape list simply omitted the two pointers that
 * make that visible, so it enumerated a subset on which the agreement happened
 * to hold and called the result a proof.
 *
 * What actually holds is narrower and is checked below in two halves: every
 * disagreeing pair of emittable pointers shares one `/required/N/` prefix, and
 * no report ever carries two findings under one such prefix. The second half is
 * an invariant of the code, not of the alphabet, so it is pinned by running the
 * real entry point over policies that try hard to break it.
 *
 * Substituting a collator at those six sites is an *equivalent* mutation: the
 * output cannot change, so no test can catch it, and saying so with an
 * enumeration is more honest than either claiming coverage or leaving a gap.
 *
 * This package's own mixed-case identifiers are deliberately *not* on that list.
 * Collation folds case before it compares, so `maxHeaderValueLength` sorts after
 * `maxHeadersPerRoute` under a collator and before it by code unit; the same
 * happens to `requiredDirectives` against `requireIncludeSubDomains`. Both of
 * those sites are pinned in `test/ordering.test.mjs` by the sequence the tool
 * prints.
 *
 * The reason the agreement holds is worth stating, because it is what the
 * enumerations below check rather than assume. English collation gives
 * punctuation a primary weight below digits, and digits a primary weight below
 * letters -- the same relative order as their code points, for every character
 * in `[a-z0-9-]`. `_` is the character that breaks this: collation treats it as
 * punctuation, so it sorts *before* the digits, while its code point 0x5F puts
 * it after them. Every alphabet below excludes `_`, and every alphabet that
 * includes it is pinned in `test/ordering.test.mjs` instead.
 */

import assert from 'node:assert/strict'
import test from 'node:test'

import { KNOWN_DIRECTIVES, RULE_SEVERITY, byCodeUnit } from '../src/index.mjs'
import { AS_OF, apiReport, fixture, header, route } from './support.mjs'

const collator = new Intl.Collator('en')

/** Enumerate every ordered pair and assert the two comparisons agree in sign. */
function everyOrderedPairAgrees(values, label) {
  let compared = 0
  for (const left of values) {
    for (const right of values) {
      assert.equal(
        Math.sign(byCodeUnit(left, right)),
        Math.sign(collator.compare(left, right)),
        `${label}: "${left}" vs "${right}" would move under collation`,
      )
      compared += 1
    }
  }
  return compared
}

/**
 * For a set too large to enumerate pairwise, sort it both ways and compare.
 *
 * Two total orders that produce the same sorted sequence over a set agree on
 * that set, and this costs O(n log n) comparisons instead of O(n squared).
 */
function sortingAgrees(values, label) {
  const mine = [...values].sort(byCodeUnit)
  const collated = [...values].sort((left, right) => collator.compare(left, right))
  assert.deepEqual(mine, collated, `${label}: the two orders disagree somewhere in this set`)
  return values.length
}

test('the character that breaks the agreement is the one every pinned site uses', () => {
  // Stated as a check rather than as prose: `_` moves under collation, which is
  // why it is the character `test/ordering.test.mjs` is built on, and why no
  // alphabet below contains it.
  assert.equal(Math.sign(byCodeUnit('x-a', 'x_a')), -1)
  assert.equal(Math.sign(collator.compare('x-a', 'x_a')), 1)
  assert.equal(Math.sign(byCodeUnit('Z', 'a')), -1)
  assert.equal(Math.sign(collator.compare('Z', 'a')), 1)
})

test('every ordered pair of real rule ids collates exactly as it compares by code unit', () => {
  const ruleIds = Object.keys(RULE_SEVERITY)

  assert.equal(ruleIds.length > 40, true, 'the catalog must be the real one for this to prove anything')
  for (const ruleId of ruleIds) assert.match(ruleId, /^[a-z][a-z0-9-]*[a-z0-9]$/, 'the alphabet this proof rests on')
  assert.equal(everyOrderedPairAgrees(ruleIds, 'rule id'), ruleIds.length ** 2)
})

test('every ordered pair of known CSP directive names agrees too', () => {
  for (const name of KNOWN_DIRECTIVES) assert.match(name, /^[a-z][a-z0-9-]*[a-z0-9]$/)
  assert.equal(everyOrderedPairAgrees(KNOWN_DIRECTIVES, 'directive name'), KNOWN_DIRECTIVES.length ** 2)
})

/**
 * A directive name this build does not know is arbitrary, so the proof has to
 * cover the alphabet rather than a list.
 *
 * Every one- and two-character string over `[a-z0-9-]` is enumerated in full;
 * longer ones are sampled from a fixed linear congruential generator, so the
 * sample is the same on every run and on every machine. There is no
 * `Math.random` anywhere in this package, tests included.
 */
const ALPHABET = 'abcdefghijklmnopqrstuvwxyz0123456789-'

function* lcg(seed) {
  // MINSTD. The multiplier and the modulus are chosen so that their product
  // stays below Number.MAX_SAFE_INTEGER, because a generator that loses
  // precision collapses into a short cycle and the sample below would never
  // fill.
  let state = seed % 2147483647
  for (;;) {
    state = (state * 48271) % 2147483647
    yield state
  }
}

test('code-unit order and collation agree on the whole directive-name alphabet', () => {
  const short = [...ALPHABET]
  for (const first of ALPHABET) for (const second of ALPHABET) short.push(first + second)

  assert.equal(short.length, 37 + 37 * 37)
  assert.equal(sortingAgrees(short, 'every one- and two-character directive name'), short.length)
})

test('code-unit order and collation agree on a fixed sample of longer directive names', () => {
  const random = lcg(20260914)
  const sample = new Set()
  while (sample.size < 4000) {
    const length = 3 + (random.next().value % 12)
    let name = ''
    for (let index = 0; index < length; index += 1) name += ALPHABET[random.next().value % ALPHABET.length]
    sample.add(name)
  }

  const values = [...sample]
  assert.equal(sortingAgrees(values, 'sampled directive names'), 4000)
  assert.equal(values.some((name) => name.includes('-')), true, 'the sample must exercise the punctuation this rests on')
})

/**
 * The pointer vocabulary, written out as the shapes the tool can emit.
 *
 * Indices are sampled across the digit-length boundaries where a numeric
 * collator would disagree even though a plain one does not -- 9 before 10, 99
 * before 100 -- because those are the pairs a reviewer would worry about.
 */
const POINTER_SHAPES = Object.freeze([
  () => [''],
  () => ['/schemaVersion', '/label'],
  () => ['/routes', '/required', '/forbidden', '/exceptions'],
  (n) => [`/routes/${n}`, `/required/${n}`, `/forbidden/${n}`, `/exceptions/${n}`],
  (n) => [`/routes/${n}/id`, `/routes/${n}/headers`, `/routes/${n}/description`],
  (n) => [`/required/${n}/header`, `/required/${n}/allowedValues`, `/required/${n}/minMaxAge`],
  (n) => [`/required/${n}/requiredDirectives/${n}`, `/required/${n}/forbiddenSources/${n}`, `/required/${n}/allowedValues/${n}`],
  (n) => [`/exceptions/${n}/route`, `/exceptions/${n}/expires`, `/exceptions/${n}/reason`, `/exceptions/${n}/header`],
  (n) => [`/forbidden/${n}/header`, `/forbidden/${n}/description`],
  (n) => [`/routes/${n}/headers/${n}`, `/routes/${n}/headers/${n}/name`, `/routes/${n}/headers/${n}/value`],
  // The two that were missing. `compileRequirement` type-checks these in a loop
  // over the key names, so they are emitted exactly as spelled, capital letters
  // and all -- and they are what breaks the agreement.
  (n) => [`/required/${n}/requireIncludeSubDomains`, `/required/${n}/requirePreload`],
])

/** The prefix under which, and only under which, the two orders disagree. */
const ONE_REQUIREMENT = /^(\/required\/\d+)\//

function emittablePointers() {
  const pointers = new Set()
  for (const build of POINTER_SHAPES) {
    for (const index of [0, 1, 2, 9, 10, 11, 99, 100, 101]) {
      for (const pointer of build(index)) pointers.add(pointer)
    }
  }
  return [...pointers]
}

test('emittable JSON Pointers disagree, and only ever within one requirement', () => {
  const values = emittablePointers()

  assert.equal(values.length > 100, true)
  for (const pointer of values) assert.match(pointer, /^(\/[A-Za-z0-9]+)*$/, 'the alphabet these pointers are drawn from')

  const disagreements = []
  for (const left of values) {
    for (const right of values) {
      if (Math.sign(byCodeUnit(left, right)) !== Math.sign(collator.compare(left, right))) disagreements.push([left, right])
    }
  }

  assert.notEqual(
    disagreements.length,
    0,
    'the shape list has stopped emitting the pointers that disagree, so this file is back to proving a subset',
  )
  for (const [left, right] of disagreements) {
    const prefix = ONE_REQUIREMENT.exec(left)
    assert.notEqual(prefix, null, `"${left}" vs "${right}" disagree outside a single requirement`)
    assert.equal(
      right.startsWith(`${prefix[1]}/`),
      true,
      `"${left}" vs "${right}" disagree across two different requirements`,
    )
  }
})

/**
 * The invariant that makes the disagreement unobservable, pinned by behaviour.
 *
 * Two findings whose pointers disagree would have to sit under the same
 * `/required/N/` prefix, and no report carries two of those: every diagnostic
 * `compileRequirement` raises about one entry is followed by a `return null`,
 * and the duplicate-header check that also anchors there only runs on an entry
 * that compiled without one. That is a property of the code, so an alphabet
 * cannot prove it and each case below drives the real entry point instead.
 *
 * If this ever stops holding, the pointer comparison in `compareFindings`
 * becomes observable and a collator swapped in for it would reorder a real
 * report. That is the whole reason this is a test and not a sentence.
 */
test('no report carries two findings under one requirement', async () => {
  const policies = [
    // Four independent faults in one entry: the first one ends it.
    { required: [{ header: 'strict-transport-security', allowedValues: [], minMaxAge: 'soon', requireIncludeSubDomains: 'yes', requirePreload: 'no' }] },
    // The two pointers that disagree, both wrong at once.
    { required: [{ header: 'strict-transport-security', requireIncludeSubDomains: 'yes', requirePreload: 'no' }] },
    // A bad nested value and a bad sibling.
    { required: [{ header: 'content-security-policy', requiredDirectives: [''], forbiddenSources: [] }] },
    // An entry that compiles, then collides with the one before it.
    { required: [{ header: 'x-frame-options' }, { header: 'x-frame-options' }] },
    // An entry that compiles, then contradicts a forbidden entry.
    { required: [{ header: 'x-frame-options' }], forbidden: [{ header: 'x-frame-options' }] },
    // A stray key beside a fault the checks would otherwise reach.
    { required: [{ header: 'strict-transport-security', minMaxAge: -1, nonsense: true }] },
  ]

  for (const policy of policies) {
    const report = await apiReport(fixture(policy, [route('r', [header('X-Frame-Options', 'DENY')])]), { asOf: AS_OF })

    const seen = new Map()
    for (const finding of report.findings) {
      const prefix = ONE_REQUIREMENT.exec(finding.location.pointer)
      if (prefix === null) continue
      const already = seen.get(prefix[1])
      assert.equal(
        already,
        undefined,
        `${JSON.stringify(policy)} produced two findings under ${prefix[1]}: ${already} and ${finding.location.pointer}`,
      )
      seen.set(prefix[1], finding.location.pointer)
    }
    assert.notEqual(report.findings.length, 0, `${JSON.stringify(policy)} raised nothing, so it pins nothing`)
  }
})
