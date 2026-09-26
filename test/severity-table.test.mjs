/**
 * The severity table asserted against the documented catalog, in both
 * directions.
 *
 * This is a consistency check, not the guarantee. A frozen table, a markdown
 * catalog and a test's expected map are three declarations, and one edit that
 * changes all three leaves every assertion here satisfied.
 * `test/severity-exit.test.mjs` and `test/severity-word.test.mjs` are where
 * severity is actually pinned, by exit codes and printed words that no edit to a
 * declaration can satisfy.
 *
 * What this file does earn: a rule that exists in the code and not in the
 * documentation, or the other way round, is caught the moment either moves.
 */

import assert from 'node:assert/strict'
import { readFile } from 'node:fs/promises'
import { join } from 'node:path'
import test from 'node:test'

import { RULE_SEVERITY, WAIVABLE_RULES } from '../src/index.mjs'
import { projectDirectory } from './support.mjs'

const SEVERITIES = ['error', 'info', 'warning']

async function documentedCatalog() {
  const text = await readFile(join(projectDirectory, 'docs/header-rules.md'), 'utf8')
  const rows = new Map()
  const pattern = /^\| `([a-z0-9-]+)` \| (error|warning|info) \| (yes|no) \|$/
  for (const line of text.split(String.fromCharCode(0x0a))) {
    const match = pattern.exec(line.trim())
    if (match !== null) rows.set(match[1], { severity: match[2], waivable: match[3] === 'yes' })
  }
  return rows
}

test('the table is frozen, ordered, and uses only the three documented severities', () => {
  assert.equal(Object.isFrozen(RULE_SEVERITY), true)
  const ids = Object.keys(RULE_SEVERITY)
  assert.deepEqual(ids, [...ids].sort())
  for (const [id, severity] of Object.entries(RULE_SEVERITY)) {
    assert.equal(SEVERITIES.includes(severity), true, `${id} has an undocumented severity`)
    assert.match(id, /^[a-z][a-z0-9-]*[a-z0-9]$/, `${id} is not a stable kebab-case rule id`)
  }
})

test('every rule in the code is documented with the same severity', async () => {
  const documented = await documentedCatalog()

  for (const [id, severity] of Object.entries(RULE_SEVERITY)) {
    assert.equal(documented.has(id), true, `${id} is in the code and not in docs/header-rules.md`)
    assert.equal(documented.get(id).severity, severity, `${id} has a different severity in the catalog`)
  }
})

test('every rule in the catalog exists in the code', async () => {
  const documented = await documentedCatalog()

  assert.equal(documented.size > 40, true, 'the catalog must have been parsed for this to prove anything')
  for (const id of documented.keys()) {
    assert.equal(Object.hasOwn(RULE_SEVERITY, id), true, `${id} is documented and not in the code`)
  }
  assert.equal(documented.size, Object.keys(RULE_SEVERITY).length)
})

test('the waivable set is frozen, ordered, and names only rules that exist', () => {
  assert.equal(Object.isFrozen(WAIVABLE_RULES), true)
  assert.deepEqual(WAIVABLE_RULES, [...WAIVABLE_RULES].sort())
  assert.equal(new Set(WAIVABLE_RULES).size, WAIVABLE_RULES.length)
  for (const id of WAIVABLE_RULES) {
    assert.equal(Object.hasOwn(RULE_SEVERITY, id), true, `${id} is waivable and not in the severity table`)
  }
})

test('the documented waivable column matches the waivable set in both directions', async () => {
  const documented = await documentedCatalog()
  const waivable = new Set(WAIVABLE_RULES)

  for (const [id, row] of documented) {
    assert.equal(row.waivable, waivable.has(id), `${id} disagrees about whether a waiver can excuse it`)
  }
})

/**
 * The one structural claim worth making here rather than behaviourally: no rule
 * that reports missing evidence is waivable.
 *
 * The behavioural cases live in `test/exceptions.test.mjs`, which drives a
 * capture with a field recorded twice through a waiver naming exactly that route
 * and field and watches it exit 2 anyway. This states the rule the code follows
 * so that adding a new evidence rule to the waivable set fails here too.
 */
test('no rule that says the evidence is missing can be waived', () => {
  const evidenceRules = [
    'csp-analysis-incomplete',
    'csp-unparseable',
    'header-duplicated',
    'header-invalid',
    'header-value-control-character',
    'header-value-too-long',
    'identifier-invalid',
    'input-not-json',
    'input-not-utf8',
    'input-too-large',
    'input-unreadable',
    'no-checks-performed',
    'path-escapes-root',
    'pattern-unsupported',
    'time-budget-exceeded',
    'too-many-exceptions',
    'too-many-findings',
    'too-many-headers',
    'too-many-requirements',
    'too-many-routes',
  ]

  for (const id of evidenceRules) {
    assert.equal(Object.hasOwn(RULE_SEVERITY, id), true, `${id} is not a rule`)
    assert.equal(WAIVABLE_RULES.includes(id), false, `${id} must never be waivable`)
  }
})
