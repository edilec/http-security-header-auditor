import assert from 'node:assert/strict'
import test from 'node:test'

import { parseFailureDetail } from '../src/text.mjs'
import { CANARY, cliHuman, clean } from './support.mjs'

/**
 * A parse failure does not quote the file it failed on.
 *
 * V8 reports a parse failure two ways, and one of them embeds the input:
 * `Unexpected token 'A', "AKIAIOSFODNN7EXAMPLE" is not valid JSON`. The
 * `input-not-json` finding interpolated that message, so a capture short enough
 * to be nothing but a credential was reproduced in full on stdout -- and a
 * capture is the file in this package most likely to hold a session cookie or
 * an authorization header. `excerpt` never helped and never could: it cuts from
 * the end and the quoted span is at the front.
 *
 * The prefix walk is the same one `test/sanitisation.test.mjs` uses, and for
 * the same reason: V8 quotes a ten-character window once the input is long
 * enough, so an assertion on the whole string alone passes while ten characters
 * of the secret still ship.
 */

const SHORTEST_PREFIX = 8

/** Run the real binary with `capture.json` replaced by the given text. */
async function runWith(text, extraArgs = []) {
  const result = await cliHuman({ ...clean(), 'capture.json': text }, extraArgs)
  for (let length = SHORTEST_PREFIX; length <= CANARY.length; length += 1) {
    const prefix = CANARY.slice(0, length)
    assert.equal(result.stdout.includes(prefix), false, `stdout carried the first ${length} characters of the canary`)
    assert.equal(result.stderr.includes(prefix), false, `stderr carried the first ${length} characters of the canary`)
  }
  return result
}

test('a capture that is only a credential is not echoed by its own parse error', async () => {
  const { code, report, stderr } = await runWith(CANARY)
  assert.equal(code, 2)

  const finding = report.findings.find((row) => row.ruleId === 'input-not-json')
  assert.notEqual(finding, undefined, 'the run still said the capture was not JSON')
  assert.match(finding.message, /token/, 'the diagnostic still says what went wrong')
  assert.match(stderr, /input-not-json/, 'the human report still names the rule')
})

test('a capture that fails after a valid property keeps its position, line and column', async () => {
  // V8 answers this one with the safe spelling: a position and no quoted span.
  // A parse error that says nothing is a different defect.
  const { report } = await runWith(`{"schemaVersion": "1" ${CANARY}}`)

  const finding = report.findings.find((row) => row.ruleId === 'input-not-json')
  assert.match(finding.message, /at position \d+/, 'the position a reader needs is still there')
  assert.match(finding.message, /line \d+ column \d+/, 'line and column are still there')
})

test('a secret deep inside a longer capture is not echoed by the windowed spelling', async () => {
  // The third V8 spelling quotes a window rather than a prefix and carries no
  // position; only the offending token survives it.
  const { report } = await runWith(`{"schemaVersion": "1", "routes": ${CANARY}}`)

  const finding = report.findings.find((row) => row.ruleId === 'input-not-json')
  assert.match(finding.message, /unexpected token/)
})

test('parseFailureDetail keeps the position and drops the quoted input', () => {
  const caught = (text) => {
    try {
      JSON.parse(text)
      return null
    } catch (error) {
      return error
    }
  }

  const quoted = caught(CANARY)
  assert.equal(quoted.message.includes(CANARY), true, 'V8 still quotes the input, so this test still has a subject')
  assert.equal(parseFailureDetail(quoted).includes(CANARY.slice(0, SHORTEST_PREFIX)), false)

  const detail = parseFailureDetail(caught(`{"a": 1 ${CANARY}}`))
  assert.equal(detail.includes(CANARY.slice(0, SHORTEST_PREFIX)), false)
  assert.match(detail, /at position \d+ \(line \d+ column \d+\)$/)

  assert.equal(parseFailureDetail(caught('password=hunter2-correct-horse')).includes('password'), false)
  assert.equal(parseFailureDetail(caught('')), 'Unexpected end of JSON input')
  assert.equal(parseFailureDetail(undefined), 'the file could not be parsed as JSON')
})
