import assert from 'node:assert/strict'
import test from 'node:test'

import {
  DEFAULT_LIMITS,
  KNOWN_DIRECTIVES,
  OTHER_DIRECTIVES,
  SOURCE_LIST_DIRECTIVES,
  classifySource,
  parseCsp,
  parseHsts,
  redactSource,
} from '../src/index.mjs'

const kinds = (result) => result.issues.map((issue) => issue.kind)

test('a plain policy parses into its directives with no issue at all', () => {
  const result = parseCsp("default-src 'self'; frame-ancestors 'none'; upgrade-insecure-requests", DEFAULT_LIMITS)

  assert.equal(result.ok, true)
  assert.deepEqual(result.directives.map((directive) => directive.name), ['default-src', 'frame-ancestors', 'upgrade-insecure-requests'])
  assert.deepEqual(result.directives.map((directive) => directive.kind), ['source-list', 'source-list', 'other'])
  assert.deepEqual(kinds(result), [])
})

test('extra whitespace, trailing semicolons and mixed case are all ordinary policies', () => {
  const result = parseCsp("  DEFAULT-SRC   'SELF'  ;; frame-ancestors\t'none' ; ", DEFAULT_LIMITS)

  assert.equal(result.ok, true)
  assert.deepEqual(result.directives.map((directive) => directive.name), ['default-src', 'frame-ancestors'])
  assert.deepEqual(kinds(result), [])
})

test("'none' beside another source is reported as a contradiction", () => {
  const result = parseCsp("default-src 'none' https://cdn.example.invalid", DEFAULT_LIMITS)

  assert.deepEqual(kinds(result), ['none-with-sources'])
  assert.deepEqual(result.issues[0].detail, ['https://cdn.example.invalid'])
})

test("'unsafe-inline' beside a nonce is reported, and beside a hash too", () => {
  const withNonce = parseCsp("script-src 'self' 'unsafe-inline' 'nonce-abc123'", DEFAULT_LIMITS)
  assert.deepEqual(kinds(withNonce), ['unsafe-inline-with-nonce'])
  assert.equal(withNonce.issues[0].detail, 'a nonce')

  const withHash = parseCsp("script-src 'unsafe-inline' 'sha256-abc='", DEFAULT_LIMITS)
  assert.deepEqual(kinds(withHash), ['unsafe-inline-with-nonce'])
  assert.equal(withHash.issues[0].detail, 'a hash')
})

test("'unsafe-inline' on its own is not a contradiction, and a nonce on its own is not either", () => {
  assert.deepEqual(kinds(parseCsp("script-src 'self' 'unsafe-inline'", DEFAULT_LIMITS)), [])
  assert.deepEqual(kinds(parseCsp("script-src 'nonce-abc123'", DEFAULT_LIMITS)), [])
})

test('a wildcard shadowing named hosts is reported, and a wildcard alone is not', () => {
  const shadowing = parseCsp('img-src * https://images.example.invalid', DEFAULT_LIMITS)
  assert.deepEqual(kinds(shadowing), ['wildcard-with-sources'])
  assert.deepEqual(shadowing.issues[0].detail, ['https://images.example.invalid'])

  assert.deepEqual(kinds(parseCsp('img-src *', DEFAULT_LIMITS)), [])
  assert.deepEqual(kinds(parseCsp("img-src * 'self'", DEFAULT_LIMITS)), [], "'self' is a keyword, not a host the wildcard shadows")
})

test('a directive declared twice keeps the first and reports the second', () => {
  const result = parseCsp("img-src 'self'; img-src https://images.example.invalid", DEFAULT_LIMITS)

  assert.deepEqual(kinds(result), ['directive-duplicate'])
  assert.equal(result.issues[0].firstIndex, 0)
  assert.equal(result.issues[0].index, 1)
  assert.deepEqual(result.directives.map((directive) => directive.sources), [["'self'"]])
})

test('a repeated source inside one directive is reported once', () => {
  const result = parseCsp("script-src 'self' 'SELF'", DEFAULT_LIMITS)

  assert.deepEqual(kinds(result), ['source-duplicate'])
  assert.equal(result.issues[0].source, "'SELF'", 'the repeat is named as it was written, after the case-insensitive comparison caught it')
})

test('a directive name outside the grammar is reported and its whole segment is discarded', () => {
  const result = parseCsp("script_src 'self'; default-src 'self'", DEFAULT_LIMITS)

  assert.deepEqual(kinds(result), ['directive-malformed'])
  assert.deepEqual(result.directives.map((directive) => directive.name), ['default-src'])
})

test('a directive this build does not know is recorded and not analysed', () => {
  const result = parseCsp("future-directive 'none' https://a.example.invalid", DEFAULT_LIMITS)

  assert.deepEqual(kinds(result), ['directive-unknown'])
  assert.deepEqual(result.directives.map((directive) => directive.kind), ['other'])
})

test('source-list analysis never runs on a directive that takes no source list', () => {
  // `sandbox` takes sandboxing flags and `report-uri` takes URIs. Running the
  // wildcard or 'none' rules over either would invent a contradiction.
  assert.deepEqual(kinds(parseCsp('sandbox allow-scripts allow-same-origin', DEFAULT_LIMITS)), [])
  assert.deepEqual(kinds(parseCsp('report-uri /a /b', DEFAULT_LIMITS)), [])
  assert.deepEqual(kinds(parseCsp("trusted-types 'none' default", DEFAULT_LIMITS)), [])
})

test('the directive bound refuses the whole policy rather than reading a prefix of it', () => {
  const many = Array.from({ length: 6 }, (_, index) => `img-src${index} 'self'`).join('; ')
  const result = parseCsp(many, { ...DEFAULT_LIMITS, maxCspDirectives: 5 })

  assert.equal(result.ok, false)
  assert.equal(result.reason, 'too-many-directives')
  assert.equal(result.limit, 5)
  assert.equal(Object.hasOwn(result, 'directives'), false, 'a refused policy yields no directives at all')
})

test('the source bound refuses the whole policy too', () => {
  const sources = Array.from({ length: 6 }, (_, index) => `https://h${index}.example.invalid`).join(' ')
  const result = parseCsp(`img-src ${sources}`, { ...DEFAULT_LIMITS, maxCspSources: 5 })

  assert.equal(result.ok, false)
  assert.equal(result.reason, 'too-many-sources')
  assert.equal(result.directive, 'img-src')
})

test('classifySource names the classes the contradiction rules are written against', () => {
  assert.equal(classifySource('*'), 'wildcard')
  assert.equal(classifySource("'NONE'"), 'none')
  assert.equal(classifySource("'nonce-abc'"), 'nonce')
  assert.equal(classifySource("'sha384-abc'"), 'hash')
  assert.equal(classifySource("'self'"), 'keyword')
  assert.equal(classifySource('https://a.example.invalid'), 'host')
  assert.equal(classifySource('data:'), 'host')
})

test('a nonce and a hash are never reproduced in a report', () => {
  assert.equal(redactSource("'nonce-r4nd0mv4lu3'"), "'nonce-...'")
  assert.equal(redactSource("'sha256-Zm9vYmFy'"), "'sha256-...'")
  assert.equal(redactSource("'self'"), "'self'")
  assert.equal(redactSource('https://a.example.invalid'), 'https://a.example.invalid')
})

test('the known directive catalog is one list with no overlap and stable order', () => {
  assert.equal(KNOWN_DIRECTIVES.length, SOURCE_LIST_DIRECTIVES.length + OTHER_DIRECTIVES.length)
  assert.equal(new Set(KNOWN_DIRECTIVES).size, KNOWN_DIRECTIVES.length)
  assert.deepEqual(KNOWN_DIRECTIVES, [...KNOWN_DIRECTIVES].sort())
  for (const name of KNOWN_DIRECTIVES) assert.match(name, /^[a-z][a-z0-9-]*$/)
})

test('HSTS parses its three tokens and nothing else', () => {
  const result = parseHsts('max-age=31536000; includeSubDomains; preload')

  assert.deepEqual(result.parsed, { maxAge: 31536000, includeSubDomains: true, preload: true })
  assert.deepEqual(kinds(result), [])
})

test('HSTS token names are case-insensitive and a quoted max-age is accepted', () => {
  const result = parseHsts('MAX-AGE="600"; INCLUDESUBDOMAINS')

  assert.deepEqual(result.parsed, { maxAge: 600, includeSubDomains: true, preload: false })
  assert.deepEqual(kinds(result), [])
})

test('a max-age this build cannot read is reported and never coerced', () => {
  const result = parseHsts('max-age=1e7')

  assert.equal(result.parsed.maxAge, null)
  assert.deepEqual(kinds(result), ['hsts-max-age-malformed'])
})

test('a repeated or unrecognised HSTS token is reported', () => {
  assert.deepEqual(kinds(parseHsts('max-age=600; max-age=700')), ['hsts-directive-duplicate'])
  assert.deepEqual(kinds(parseHsts('max-age=600; includeSubdomain')), ['hsts-directive-unknown'])
})

test('an HSTS field with no max-age reports no duration rather than zero', () => {
  const result = parseHsts('includeSubDomains')

  assert.equal(result.parsed.maxAge, null)
  assert.deepEqual(kinds(result), [])
})
