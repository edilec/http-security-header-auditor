import assert from 'node:assert/strict'
import test from 'node:test'

import {
  MAX_HEADER_NAME_LENGTH,
  MAX_IDENTIFIER_LENGTH,
  asciiLower,
  byCodeUnit,
  decodeUtf8,
  describeValue,
  excerpt,
  hasForbiddenCharacter,
  isCalendarDate,
  isHeaderName,
  isIdentifier,
  isPlainObject,
  looksLikePattern,
} from '../src/index.mjs'
import { FORBIDDEN } from './support.mjs'

test('byCodeUnit orders by code unit, including where collation would not', () => {
  assert.equal(byCodeUnit('a', 'a'), 0)
  assert.equal(byCodeUnit('Z-route', 'a-route') < 0, true)
  assert.equal(byCodeUnit('x-audit', 'x_audit') < 0, true)
  assert.equal(byCodeUnit('README', 'assets') < 0, true)
})

test('every class the report contract names is detected in an identifier position', () => {
  for (const [name, character] of Object.entries(FORBIDDEN)) {
    assert.equal(hasForbiddenCharacter(`x${character}y`), true, `${name} was not detected`)
    assert.equal(isIdentifier(`route${character}id`), false, `${name} passed isIdentifier`)
    assert.equal(isHeaderName(`x-${character}-h`), false, `${name} passed isHeaderName`)
  }
})

test('excerpt removes every class, collapses whitespace and bounds the result', () => {
  for (const [name, character] of Object.entries(FORBIDDEN)) {
    const out = excerpt(`before${character}after`)
    assert.equal(hasForbiddenCharacter(out), false, `${name} survived excerpt`)
    assert.equal(out, 'before after')
  }
  assert.equal(excerpt('a\tb\r\nc'), 'a b c')
  assert.equal(excerpt('x'.repeat(50), 10), `${'x'.repeat(10)}...`)
  assert.equal(excerpt('  padded  '), 'padded')
})

test('plain right-to-left text is not touched, because it needs no override to be right-to-left', () => {
  const hebrew = String.fromCharCode(0x05d0, 0x05d1, 0x05d2)
  assert.equal(hasForbiddenCharacter(hebrew), false)
  assert.equal(excerpt(`a${hebrew}b`), `a${hebrew}b`)
})

test('asciiLower folds ASCII letters and changes nothing else, including length', () => {
  assert.equal(asciiLower('Content-Security-Policy'), 'content-security-policy')
  assert.equal(asciiLower('X_Forwarded_Proto'), 'x_forwarded_proto')
  const dottedI = String.fromCharCode(0x130)
  assert.equal(asciiLower(dottedI), dottedI)
  assert.equal(asciiLower(dottedI).length, 1, 'a Unicode fold would have produced two code points here')
})

test('isIdentifier accepts the route ids a real capture carries and refuses the rest', () => {
  for (const value of ['app-root', 'api/v1/orders', 'A1', 'a.b:c+d', '0']) {
    assert.equal(isIdentifier(value), true, `${value} should be a route id`)
  }
  for (const value of ['', '-leading', '/leading', 'has space', 'a'.repeat(MAX_IDENTIFIER_LENGTH + 1), 7, null, undefined]) {
    assert.equal(isIdentifier(value), false, `${String(value)} should not be a route id`)
  }
})

test('isHeaderName accepts the whole RFC 9110 token alphabet and refuses everything outside it', () => {
  for (const value of ['content-security-policy', 'X_Forwarded_Proto', "x'y", 'a.b', 'x~z', 'X-9']) {
    assert.equal(isHeaderName(value), true, `${value} is a token`)
  }
  for (const value of ['', 'has space', 'a:b', 'a/b', 'a,b', 'a'.repeat(MAX_HEADER_NAME_LENGTH + 1), 3, null]) {
    assert.equal(isHeaderName(value), false, `${String(value)} is not a token`)
  }
})

test('looksLikePattern catches the shapes a waiver must not be allowed to guess at', () => {
  for (const value of ['/api/*', 'a?', '{env}.example.invalid', 'a[b]']) {
    assert.equal(looksLikePattern(value), true, `${value} is a pattern`)
  }
  assert.equal(looksLikePattern('api/v1/orders'), false)
  assert.equal(looksLikePattern(7), false)
})

test('isCalendarDate accepts real dates, refuses impossible ones, and needs no Date to do it', () => {
  for (const value of ['2026-03-01', '2024-02-29', '2000-02-29', '1999-12-31']) {
    assert.equal(isCalendarDate(value), true, `${value} is a date`)
  }
  for (const value of ['2026-02-30', '2026-13-01', '2026-00-10', '2026-01-00', '2023-02-29', '1900-02-29', '26-03-01', '2026-3-1', '2026-03-01T00:00:00Z', 'tomorrow', '', 20260301, null]) {
    assert.equal(isCalendarDate(value), false, `${String(value)} is not a date`)
  }
})

test('two calendar dates compare correctly with a plain string comparison', () => {
  assert.equal('2025-12-31' < '2026-01-01', true)
  assert.equal('2026-03-01' < '2026-03-02', true)
  assert.equal('2026-09-30' < '2026-03-01', false)
})

test('decoding is the decoder decision, never an inference from decoded text', () => {
  assert.deepEqual(decodeUtf8(new Uint8Array([0x7b, 0x7d])), { ok: true, text: '{}' })

  // A file that legitimately holds U+FFFD decodes fine; a lenient decoder plus a
  // hunt for U+FFFD could not tell these two apart, which is the confusion that
  // let an unread input report a pass in a sibling tool.
  const literalReplacement = new TextEncoder().encode(`"${String.fromCharCode(0xfffd)}"`)
  const decoded = decodeUtf8(literalReplacement)
  assert.equal(decoded.ok, true)
  assert.equal(decoded.text.includes(String.fromCharCode(0xfffd)), true)

  assert.deepEqual(decodeUtf8(new Uint8Array([0xff, 0xfe, 0x00])), { ok: false, reason: 'not-utf8' })
  assert.equal(decodeUtf8(new Uint8Array([0xc3])).ok, false)
})

test('describeValue says what a refused value was without reproducing any of it', () => {
  assert.equal(describeValue(undefined), 'nothing')
  assert.equal(describeValue(null), 'null')
  assert.equal(describeValue(true), 'true')
  assert.equal(describeValue(4), 'an integer')
  assert.equal(describeValue(4.5), 'a number')
  assert.equal(describeValue('secret-value'), 'a string of 12 character(s)')
  assert.equal(describeValue([1, 2]), 'an array of 2 item(s)')
  assert.equal(describeValue({}), 'an object')
  assert.equal(describeValue('hunter2').includes('hunter2'), false)
})

test('isPlainObject refuses arrays, null and dressed-up class instances', () => {
  assert.equal(isPlainObject({}), true)
  assert.equal(isPlainObject(Object.create(null)), true)
  assert.equal(isPlainObject([]), false)
  assert.equal(isPlainObject(null), false)
  assert.equal(isPlainObject(new Map()), false)
  assert.equal(isPlainObject(new Date(0)), false)
})
