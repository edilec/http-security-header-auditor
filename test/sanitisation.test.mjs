/**
 * Sanitisation, checked across the whole report rather than one field.
 *
 * Four tools in this catalog stripped C0 and the line separators and let the C1
 * range through; one sanitised its evidence field carefully and let a record id
 * forge whole lines. So every case below plants a character in a position that
 * is *not* an excerpt -- a JSON key, an identifier-shaped field, a reason
 * somebody wrote -- and then walks the entire serialized report and the entire
 * stderr looking for any of the classes anywhere.
 *
 * A test that checks the field somebody remembered is a test the next field
 * passes for free.
 */

import assert from 'node:assert/strict'
import test from 'node:test'

import { hasForbiddenCharacter } from '../src/index.mjs'
import { CANARY, FORBIDDEN, apiReport, cliHuman, cliReport, header, route } from './support.mjs'

const BASE_POLICY = { schemaVersion: '1', required: [{ header: 'x-content-type-options' }] }

/**
 * A stream is checked line by line.
 *
 * The report is pretty-printed and the human summary is a list of lines, so
 * both streams legitimately carry U+000A as structure. Splitting on it and
 * checking what is left refuses every other class -- carriage return, NEL, the
 * 8-bit CSI, the separators, the bidi overrides -- and the line *count* is
 * pinned separately, which is what catches a forged line.
 */
function assertStreamClean(stream, label) {
  const lines = stream.split(String.fromCharCode(0x0a))
  lines.forEach((line, index) => {
    assert.equal(hasForbiddenCharacter(line), false, `${label} line ${index} carried a forbidden character`)
  })
  return lines
}

/** Walk every string in the report -- keys and values alike -- and refuse any class. */
function assertClean(value, where) {
  if (typeof value === 'string') {
    assert.equal(hasForbiddenCharacter(value), false, `${where} carried a forbidden character`)
    return
  }
  if (Array.isArray(value)) {
    value.forEach((item, index) => assertClean(item, `${where}[${index}]`))
    return
  }
  if (value !== null && typeof value === 'object') {
    for (const [key, item] of Object.entries(value)) {
      assert.equal(hasForbiddenCharacter(key), false, `${where} had a forbidden character in the key itself`)
      assertClean(item, `${where}.${key}`)
    }
  }
}

test('a character arriving through a JSON key survives nowhere in the report', async () => {
  for (const [name, character] of Object.entries(FORBIDDEN)) {
    const report = await apiReport({
      'policy.json': { schemaVersion: '1', [`required${character}`]: [] },
      'capture.json': { schemaVersion: '1', routes: [] },
    })

    assert.equal(report.status, 'incomplete', `${name} should not have produced a usable policy`)
    assertClean(report, `report for ${name}`)
    assertClean(JSON.parse(JSON.stringify(report)), `round-tripped report for ${name}`)
  }
})

test('a character arriving through an identifier-shaped field survives nowhere', async () => {
  for (const [name, character] of Object.entries(FORBIDDEN)) {
    const report = await apiReport({
      'policy.json': BASE_POLICY,
      'capture.json': {
        schemaVersion: '1',
        routes: [{ id: `route${character}id`, headers: [{ name: `x-${character}-field`, value: 'v' }] }],
      },
    })

    assertClean(report, `report for ${name}`)
    assert.equal(report.status, 'incomplete', `${name} in a route id must not be audited as if it were a name`)
  }
})

test('a character arriving through a field value is refused and never reproduced', async () => {
  for (const [name, character] of Object.entries(FORBIDDEN)) {
    const report = await apiReport({
      'policy.json': BASE_POLICY,
      'capture.json': {
        schemaVersion: '1',
        routes: [route('ok', [header('X-Content-Type-Options', `nosniff${character}injected`)])],
      },
    })

    assertClean(report, `report for ${name}`)
    assert.equal(JSON.stringify(report).includes('injected'), false, `${name} let a refused value into the report`)
  }
})

test('a character arriving through a waiver reason survives nowhere', async () => {
  for (const [name, character] of Object.entries(FORBIDDEN)) {
    const report = await apiReport({
      'policy.json': {
        ...BASE_POLICY,
        exceptions: [{ route: 'bare', header: 'x-content-type-options', reason: `accepted${character}by nobody`, expires: '2099-12-31' }],
      },
      'capture.json': { schemaVersion: '1', routes: [route('bare', [])] },
    }, { asOf: '2026-03-01' })

    assertClean(report, `report for ${name}`)
  }
})

test('a character arriving through a route description survives nowhere', async () => {
  for (const [name, character] of Object.entries(FORBIDDEN)) {
    const report = await apiReport({
      'policy.json': BASE_POLICY,
      'capture.json': {
        schemaVersion: '1',
        routes: [route('bare', [], `the ${character} shell`)],
      },
    })

    assertClean(report, `report for ${name}`)
  }
})

test('a character arriving through a CSP directive name survives nowhere', async () => {
  for (const [name, character] of Object.entries(FORBIDDEN)) {
    const report = await apiReport({
      'policy.json': { schemaVersion: '1', required: [{ header: 'content-security-policy' }] },
      'capture.json': {
        schemaVersion: '1',
        routes: [route('csp', [header('Content-Security-Policy', `default${character}src 'self'`)])],
      },
    })

    assertClean(report, `report for ${name}`)
  }
})

test('both streams of the real binary are clean, not only the parsed report', async () => {
  for (const [name, character] of Object.entries(FORBIDDEN)) {
    const { stdout, stderr } = await cliHuman({
      'policy.json': { schemaVersion: '1', [`required${character}`]: [], required: [{ header: 'x-content-type-options' }] },
      'capture.json': {
        schemaVersion: '1',
        routes: [route('bare', [], `note ${character} here`)],
      },
    }, [])

    assertStreamClean(stdout, `stdout for ${name}`)
    assertStreamClean(stderr, `stderr for ${name}`)
  }
})

test('an untrusted string cannot forge a line in the human summary', async () => {
  // NEL is a line break to a great many consumers and it is not in the C0
  // range, which is the gap four tools in this catalog left open. Two vectors
  // try to open a second line here: a JSON key, which reaches a message printed
  // on stderr, and a waiver reason, which reaches a finding's evidence.
  const NEL = String.fromCharCode(0x85)
  const { stdout, stderr, report } = await cliHuman({
    'policy.json': {
      schemaVersion: '1',
      [`lbl${NEL}ERROR   forged-by-a-key`]: 1,
      required: [{ header: 'x-content-type-options' }],
    },
    'capture.json': {
      schemaVersion: '1',
      routes: [route('bare', [], `line one${NEL}line two`)],
    },
  })

  assertStreamClean(stdout, 'stdout')
  const lines = assertStreamClean(stderr, 'stderr')

  // Three summary lines, one line per finding, one closing line because the run
  // is incomplete, and the trailing empty string left by the final newline.
  // Nothing the policy said added a line.
  assert.equal(report.status, 'incomplete')
  assert.equal(lines.length, 3 + report.findings.length + 1 + 1)
  assert.equal(lines.at(-1), '')
  assert.equal(
    lines.filter((line) => line.includes('forged-by-a-key')).length,
    1,
    'the forged text stayed inside the one line it belongs to',
  )
})

test('a waiver reason cannot forge a line either, and reaches the report as one field', async () => {
  const NEL = String.fromCharCode(0x85)
  const { stdout, stderr, report } = await cliHuman({
    'policy.json': {
      schemaVersion: '1',
      required: [{ header: 'x-content-type-options' }],
      exceptions: [{
        route: 'bare',
        header: 'x-content-type-options',
        reason: `agreed${NEL}forged-by-a-reason`,
        expires: '2099-12-31',
      }],
    },
    'capture.json': { schemaVersion: '1', routes: [route('bare', [])] },
  }, ['--as-of', '2026-03-01'])

  assertStreamClean(stdout, 'stdout')
  const lines = assertStreamClean(stderr, 'stderr')

  assert.equal(report.status, 'pass')
  assert.equal(lines.length, 3 + report.findings.length + 1)
  assert.equal(report.findings[0].evidence, 'agreed forged-by-a-reason', 'the break became a space inside one field')
})

/**
 * A refused value is described, never reproduced -- checked with a value that
 * looks like a credential, and checked prefix by prefix.
 *
 * The published AWS example key id stands in for a real one. A redaction test
 * that checks the whole string passes for free on a report that leaked all but
 * the last character, so every prefix of it is checked as well.
 */
test('a credential-shaped value in a refused field reaches neither stream, at any prefix', async () => {
  const { stdout, stderr, report } = await cliHuman({
    'policy.json': BASE_POLICY,
    'capture.json': {
      schemaVersion: '1',
      routes: [{
        id: 'leaky',
        headers: [
          { name: 'X-Content-Type-Options', value: `nosniff${String.fromCharCode(0x0a)}X-Api-Key: ${CANARY}` },
          { name: 'X-Amz-Key', value: 7 },
        ],
      }],
    },
  }, [])

  const serialized = JSON.stringify(report)
  for (let length = 8; length <= CANARY.length; length += 1) {
    const prefix = CANARY.slice(0, length)
    assert.equal(serialized.includes(prefix), false, `stdout carried the first ${length} characters of the canary`)
    assert.equal(stdout.includes(prefix), false, `stdout carried the first ${length} characters of the canary`)
    assert.equal(stderr.includes(prefix), false, `stderr carried the first ${length} characters of the canary`)
  }
  assert.equal(report.status, 'incomplete')
})

test('a field value that is entirely legitimate is reported unchanged', async () => {
  const report = await apiReport({
    'policy.json': { schemaVersion: '1', required: [{ header: 'referrer-policy', allowedValues: ['no-referrer'] }] },
    'capture.json': {
      schemaVersion: '1',
      routes: [route('ok', [header('Referrer-Policy', 'strict-origin-when-cross-origin')])],
    },
  })

  assert.equal(report.findings[0].evidence, 'strict-origin-when-cross-origin', 'sanitising must not mangle ordinary text')
})
