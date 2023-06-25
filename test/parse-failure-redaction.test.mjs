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

/**
 * The document that decides the order of the two shapes.
 *
 * A capture whose own text reads `at position 1` makes V8 say
 * `Unexpected token 'a', "at position 1" is not valid JSON`. Look for the
 * offset first and the match lands INSIDE the quoted span, so the slice that
 * "keeps only the position" keeps the file's own text instead. The offset is
 * therefore only consulted once no quoting shape was recognised.
 *
 * This is not a hypothetical: the previous version of this function shipped
 * the offset-first order and returned
 * `Unexpected token 'a', "at position 1` for exactly this input.
 */
const POSITION_DECOY = 'at position 1'

/** Catch the parse failure for a document, or fail loudly if there is not one. */
function parseFailureOf(text) {
  try {
    JSON.parse(text)
  } catch (error) {
    return error
  }
  throw new Error(`the fixture ${JSON.stringify(text)} parsed, so it pins nothing`)
}

test('a capture whose own text reads like a position is not quoted back', async () => {
  const { code, report, stderr } = await runWith(POSITION_DECOY)
  assert.equal(code, 2)

  const finding = report.findings.find((row) => row.ruleId === 'input-not-json')
  assert.notEqual(finding, undefined, 'the run still said the capture was not JSON')
  assert.equal(
    finding.message.includes(POSITION_DECOY),
    false,
    'the capture text came back out through the offset branch',
  )
  assert.equal(stderr.includes(POSITION_DECOY), false, 'the human summary carried the capture text')
  assert.match(finding.message, /unexpected token/, 'the diagnostic still says what went wrong')
})

test('no parse detail ever carries a double quote, whatever V8 said', () => {
  // Every V8 parse message that quotes nothing also carries no double quote at
  // all -- it quotes JSON punctuation with apostrophes. So a surviving double
  // quote means a surviving snippet, and that is the closing guard.
  const documents = [
    POSITION_DECOY,
    `${POSITION_DECOY} ${CANARY}`,
    CANARY,
    `{"${CANARY.slice(0, 8)}":${POSITION_DECOY}}`,
    `{"routes": [], "authorization": Bearer ${CANARY}}`,
    `{"a":\n${CANARY}"}`,
    'at position 9007199254740993 (line 4 column 4)',
    '"at position 1" is not valid JSON',
  ]
  for (const text of documents) {
    const detail = parseFailureDetail(parseFailureOf(text))
    assert.equal(detail.includes('"'), false, `a quoted span survived for ${JSON.stringify(text)}`)
    for (let length = SHORTEST_PREFIX; length <= CANARY.length; length += 1) {
      assert.equal(
        detail.includes(CANARY.slice(0, length)),
        false,
        `${length} characters of the canary survived for ${JSON.stringify(text)}`,
      )
    }
  }
})

test('a quoted span holding a newline is still recognised as a quoted span', () => {
  // The quoted half can run over a line break, so the shape is matched with the
  // dot-all flag. Drop the flag and this span is not recognised as a span at
  // all, the offset branch runs instead, and the document comes back out.
  const failure = parseFailureOf(`a\n${POSITION_DECOY}`)
  assert.match(failure.message, /^Unexpected token 'a', "/, 'V8 still quotes this one, so the test still has a subject')
  assert.equal(failure.message.includes('\n'), true, 'the quoted span still straddles a line break')

  const detail = parseFailureDetail(failure)
  assert.equal(detail, "unexpected token 'a' at the start of the document")
  assert.equal(detail.includes('"'), false)
  assert.equal(detail.includes(POSITION_DECOY), false)
})

test('a wording this build has never seen still cannot carry a snippet out', () => {
  // The closing guard, on its own. Every V8 parse message that quotes nothing
  // also carries no double quote at all, so a double quote surviving the
  // branches above means a snippet survived them -- whatever engine or version
  // produced the wording. Delete the guard and this message walks the snippet
  // out through the offset branch, because the offset sits after the quote.
  const unseen = { message: `Bad escaped character in "${CANARY}" at position 12` }
  const detail = parseFailureDetail(unseen)
  assert.equal(detail.includes(CANARY.slice(0, SHORTEST_PREFIX)), false, 'the unseen wording carried its snippet out')
  assert.equal(detail.includes('"'), false)
  assert.equal(detail, 'the file could not be parsed as JSON')
})

test('the safe positional spelling still names position, line and column', () => {
  const detail = parseFailureDetail(parseFailureOf(`{"schemaVersion": "1" ${CANARY}}`))
  assert.match(detail, /at position \d+ \(line \d+ column \d+\)$/)
  assert.equal(detail.includes(CANARY.slice(0, SHORTEST_PREFIX)), false)
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

  const decoy = caught(POSITION_DECOY)
  assert.equal(decoy.message.includes(`"${POSITION_DECOY}"`), true, 'V8 still quotes this one, so the test still has a subject')
  assert.equal(parseFailureDetail(decoy), "unexpected token 'a' at the start of the document")
})
