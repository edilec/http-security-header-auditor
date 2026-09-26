/**
 * Decoding, sanitising, ordering, and the small vocabularies this package
 * recognises.
 *
 * Nothing in this module touches the filesystem, the network, a locale or a
 * clock. Every value it handles arrived in a file this tool did not write, so
 * every value it returns is treated as data on its way to a report and never as
 * something that may shape a line of output.
 */

/**
 * Order by UTF-16 code unit.
 *
 * Locale-aware comparison -- the string method and the collator class alike --
 * reads ICU data that differs between Node builds and between hosts, and it
 * weighs punctuation differently from its code point. HTTP header names are
 * RFC 9110 tokens, so `-` and `_` both occur in real header names, and English
 * collation orders `x_audit` before `x-audit` while their code points order
 * them the other way round. A collated report would therefore list a route's
 * headers in a different order on a different machine, and two runs over the
 * same capture would not be byte-identical.
 *
 * Every order this package exposes is decided here. Neither spelling of the
 * locale-aware comparison appears anywhere in the shipped source, and
 * `test/ordering.test.mjs` pins what the tool *emits* rather than what its
 * source says -- a scan of the source cannot tell one comparator from the
 * other, so a scan is not the test.
 */
export function byCodeUnit(left, right) {
  if (left === right) return 0
  return left < right ? -1 : 1
}

/**
 * The characters no untrusted value may carry into output, in four classes.
 *
 * Built from code points rather than written literally: a literal U+2028 or
 * U+2029 inside a module is a line terminator to the JavaScript parser, and the
 * rest are invisible in an editor. Spelling each one out keeps this file plain
 * ASCII and keeps the list reviewable.
 *
 * - **C0** (U+0000-U+001F) and **DEL** (U+007F). A newline forges a line in the
 *   human report, ESC opens a terminal escape sequence, NUL truncates a value
 *   in anything that receives it through C. In a captured HTTP header a CR or
 *   LF is also evidence in its own right -- that is response splitting -- so
 *   this package refuses such a value rather than parsing it.
 * - **C1** (U+0080-U+009F). Easy to forget once C0 is handled, and two of them
 *   need no help: U+0085 NEL is a line break to a great many consumers, and
 *   U+009B is the 8-bit CSI, a terminal control introducer that needs no ESC in
 *   front of it.
 * - **Line and paragraph separators** (U+2028, U+2029).
 * - **Bidi and isolate controls** (U+200E, U+200F, U+202A-U+202E,
 *   U+2066-U+2069). U+202E RIGHT-TO-LEFT OVERRIDE reverses everything printed
 *   after it, so a policy directive named `script-src` can be displayed as
 *   something else entirely while the auditor compares the real value.
 *   Ordinary right-to-left text -- Arabic, Hebrew -- needs none of these: the
 *   letters carry their own direction, so refusing the overrides refuses
 *   nothing legitimate.
 */
const DEL_AND_C1 = `${String.fromCharCode(0x7f)}-${String.fromCharCode(0x9f)}`
const SEPARATORS = `${String.fromCharCode(0x2028)}${String.fromCharCode(0x2029)}`
const BIDI =
  `${String.fromCharCode(0x200e)}${String.fromCharCode(0x200f)}` +
  `${String.fromCharCode(0x202a)}-${String.fromCharCode(0x202e)}` +
  `${String.fromCharCode(0x2066)}-${String.fromCharCode(0x2069)}`

/**
 * Stripped from every untrusted string on its way into output -- route ids,
 * header names, header values, JSON keys, file names, pointers, messages,
 * suggestions and evidence alike, not only an excerpt field. Tab, newline and
 * carriage return are left out of this class deliberately: `excerpt` collapses
 * them into a single space in the very next step, which is the same result by a
 * shorter route.
 */
const CONTROL = new RegExp(
  `[${String.fromCharCode(0)}-${String.fromCharCode(8)}` +
  `${String.fromCharCode(11)}${String.fromCharCode(12)}` +
  `${String.fromCharCode(14)}-${String.fromCharCode(31)}` +
  `${DEL_AND_C1}${SEPARATORS}${BIDI}]`,
  'g',
)

/**
 * What an identifier or a header value may not contain: the same four classes,
 * plus the three ASCII whitespace controls `CONTROL` leaves to the collapse.
 * These values get no second pass. A route id that prints differently from the
 * value the auditor compared is a route nobody can audit, so it is refused at
 * the door.
 */
const FORBIDDEN = new RegExp(
  `[${String.fromCharCode(0)}-${String.fromCharCode(31)}` +
  `${DEL_AND_C1}${SEPARATORS}${BIDI}]`,
)

/**
 * Detects any of the four classes anywhere in a string. Exported so tests can
 * walk an entire serialized report and assert that nothing survived anywhere,
 * rather than checking the one field a developer remembered to sanitise.
 */
export function hasForbiddenCharacter(value) {
  return FORBIDDEN.test(String(value))
}

export const EXCERPT_LIMIT = 160
export const MAX_IDENTIFIER_LENGTH = 120
export const MAX_HEADER_NAME_LENGTH = 80
export const MAX_DESCRIPTION_LENGTH = 300
export const MAX_REASON_LENGTH = 300

/**
 * A bounded, single-line, control-free rendering of an untrusted string.
 *
 * Every id, header name, file name, pointer, message and piece of evidence that
 * reaches a finding goes through here. A tool in this catalog sanitised its
 * evidence carefully and left its identifiers raw, so a record id holding a
 * newline printed two lines into the human report and invented a finding that
 * was never emitted.
 */
export function excerpt(value, limit = EXCERPT_LIMIT) {
  const flattened = String(value).replace(CONTROL, ' ').replace(/\s+/g, ' ').trim()
  if (flattened.length <= limit) return flattened
  return `${flattened.slice(0, limit)}...`
}

/**
 * What a JSON parse failure may be told about itself, with the input removed.
 *
 * V8 reports a parse failure two ways, and one of them quotes the file back:
 * `Unexpected token 'A', "AKIAIOSFODNN7EXAMPLE" is not valid JSON`. A capture
 * or a policy short enough to be nothing but a credential is therefore
 * reproduced in full by its own error message, on exactly the path a malformed
 * or untrusted file takes -- and a capture is the file most likely to hold a
 * session cookie or an authorization header. `excerpt` cannot help: it strips
 * control characters and cuts from the end, and the quoted span sits at the
 * front.
 *
 * Two things make this safe and the order of them is the whole trick.
 *
 * The quoting shape is recognised BEFORE the offset is looked for. A capture
 * whose own text reads `at position 1` produces
 * `Unexpected token 'a', "at position 1" is not valid JSON`, so an
 * offset-first reading finds `at position 1` INSIDE the quoted span and slices
 * the file's own text back out as if it were V8's prose. That is not
 * hypothetical: it is what the previous version of this function did. The `s`
 * flag matters for the same reason -- the quoted span can contain a newline.
 *
 * The last line then discards any detail that still holds a double quote. That
 * is deliberate belt and braces, and it is why this function is safe against
 * wordings it has never seen: every V8 parse message that carries no quoted
 * snippet also carries no double quote at all, because it quotes JSON
 * punctuation with apostrophes. A surviving double quote therefore means a
 * surviving snippet, whatever the branches above concluded.
 *
 * Position, line and column are the useful half and carry no file content, so
 * they are kept verbatim once no quoting shape was recognised.
 */
const UNPARSEABLE = 'the file could not be parsed as JSON'

/** Where V8 puts the offending offset. Safe: an offset says nothing about content. */
const POSITION = /at position \d+(?: \(line \d+ column \d+\))?/

/** The shape that quotes the input. Recognised first; see the note above. */
const QUOTES_THE_INPUT = /^Unexpected token (.+?), (\.\.\.)?".*"(?:\.\.\.)? is not valid JSON$/s

function describeParseFailure(message) {
  const quoting = QUOTES_THE_INPUT.exec(message)
  if (quoting !== null) {
    const where = quoting[2] === undefined ? 'at the start of the document' : 'inside the document'
    return `unexpected token ${quoting[1]} ${where}`
  }
  const position = POSITION.exec(message)
  if (position !== null) return message.slice(0, position.index + position[0].length)
  if (message === 'Unexpected end of JSON input') return message
  return UNPARSEABLE
}

export function parseFailureDetail(error) {
  const message = String(error?.message ?? '')
  const detail = describeParseFailure(message)
  return detail.includes('"') ? UNPARSEABLE : detail
}

/**
 * Lowercase the ASCII letters and nothing else.
 *
 * HTTP field names are ASCII case-insensitive and so are the CSP keywords and
 * the HSTS directive names, so all three are folded before they are compared.
 * `String.prototype.toLowerCase` is not locale-sensitive, but it *is* Unicode:
 * `String.fromCharCode(0x130).toLowerCase()` returns two code points, and
 * folding a value can therefore change its length. Nothing in this package
 * wants that, and every name it folds has already been checked against an ASCII
 * alphabet, so the fold is written to match.
 */
export function asciiLower(value) {
  let out = ''
  for (let index = 0; index < value.length; index += 1) {
    const code = value.charCodeAt(index)
    out += code >= 0x41 && code <= 0x5a ? String.fromCharCode(code + 0x20) : value[index]
  }
  return out
}

/**
 * A route id: the opaque label a capture gives one captured response.
 *
 * Deliberately *not* a URL. This tool never fetches anything and never
 * discovers anything, and the surest way to keep that true is to give an
 * address nowhere to live in the input schema. A route is a name somebody chose
 * when they exported the capture; what it points at is their business and stays
 * outside this package.
 */
const IDENTIFIER = /^[A-Za-z0-9][A-Za-z0-9._:+/-]*$/

export function isIdentifier(value) {
  if (typeof value !== 'string') return false
  if (value.length === 0 || value.length > MAX_IDENTIFIER_LENGTH) return false
  if (FORBIDDEN.test(value)) return false
  return IDENTIFIER.test(value)
}

/**
 * An HTTP field name, as RFC 9110 defines a token.
 *
 * The alphabet is wider than it looks -- `!#$%&'*+-.^_\`|~` are all token
 * characters -- and real deployments do ship `X_Forwarded_Proto` and friends.
 * Accepting the whole token alphabet is what stops this tool refusing
 * legitimate captures; refusing everything outside it is what stops a field
 * name carrying a bidi override into the report.
 */
const HEADER_NAME = /^[!#$%&'*+.^_`|~0-9A-Za-z-]+$/

export function isHeaderName(value) {
  if (typeof value !== 'string') return false
  if (value.length === 0 || value.length > MAX_HEADER_NAME_LENGTH) return false
  return HEADER_NAME.test(value)
}

/**
 * Recognise a name written as a pattern rather than as a name.
 *
 * `/api/*`, `{env}.example.invalid` and `admin?` are all things somebody will
 * reasonably try to write in a route exception, and this build supports none of
 * them: an exception names one route and one header, exactly. A pattern is
 * reported as an unsupported construct that makes the run incomplete -- it is
 * never quietly matched against anything, because guessing which routes a
 * pattern covers is exactly the inference a waiver must not make.
 */
export function looksLikePattern(value) {
  return typeof value === 'string' && /[*?{}[\]]/.test(value)
}

const DAYS_IN_MONTH = Object.freeze([31, 28, 31, 30, 31, 30, 31, 31, 30, 31, 30, 31])

/**
 * A calendar date, written `YYYY-MM-DD`, validated without a `Date`.
 *
 * Exception expiry is the one place this tool compares against "now", and
 * "now" is injected as `--as-of`. Constructing a date object to validate the
 * string would drag a wall clock and a time zone into a package that has
 * neither: the built-in constructor accepts `2026-02-30` in some engines and
 * rejects it in others, and a `YYYY-MM-DD` string it does accept becomes
 * midnight UTC, which is the previous evening in most of the world. Two
 * `YYYY-MM-DD` strings compare correctly with `<`, so no date arithmetic is
 * needed and none is done.
 *
 * `test/no-network.test.mjs` scans the shipped source for that constructor and
 * for the static millisecond reader beside it, so neither spelling appears
 * anywhere above -- the scan is deliberately strict enough to trip on a mention
 * in prose, which errs towards a test that is too loud rather than a guard that
 * is too quiet.
 */
export function isCalendarDate(value) {
  if (typeof value !== 'string' || !/^\d{4}-\d{2}-\d{2}$/.test(value)) return false
  const year = Number(value.slice(0, 4))
  const month = Number(value.slice(5, 7))
  const day = Number(value.slice(8, 10))
  if (year < 1000 || month < 1 || month > 12 || day < 1) return false
  const leap = month === 2 && (year % 4 === 0 && (year % 100 !== 0 || year % 400 === 0))
  return day <= DAYS_IN_MONTH[month - 1] + (leap ? 1 : 0)
}

/**
 * Say what a refused value was, without reproducing any of it.
 *
 * A rejected field is arbitrary content from a file this tool did not write,
 * and the report goes to stdout -- a stream that is piped, logged and pasted
 * somewhere more public than the capture ever was. Echoing the value back hands
 * that content a wider audience than it had, on exactly the fields whose
 * validation exists to keep something unexpected out of the report. The pointer
 * on the finding names the exact position in the file, which is all a reader
 * needs; the value stays in the file, where it started.
 */
export function describeValue(value) {
  if (value === undefined) return 'nothing'
  if (value === null) return 'null'
  if (typeof value === 'boolean') return value ? 'true' : 'false'
  if (typeof value === 'number') return Number.isInteger(value) ? 'an integer' : 'a number'
  if (typeof value === 'string') return `a string of ${value.length} character(s)`
  if (Array.isArray(value)) return `an array of ${value.length} item(s)`
  if (typeof value === 'object') return 'an object'
  return `a ${typeof value}`
}

/**
 * Decode bytes as UTF-8, strictly.
 *
 * `fatal: true` is the whole point. Decoding leniently and then hunting for
 * U+FFFD cannot tell undecodable bytes from a file that legitimately contains a
 * replacement character, and that confusion has already let an unread input
 * report a pass in this catalog. The decoder decides; the decoded text never
 * gets a vote. Both documents go through here -- the capture and the policy
 * alike, with no exception for the one a reviewer thinks of as configuration,
 * because that is precisely where a sibling tool hardened its data path and
 * forgot.
 */
export function decodeUtf8(bytes) {
  try {
    return { ok: true, text: new TextDecoder('utf-8', { fatal: true, ignoreBOM: false }).decode(bytes) }
  } catch {
    return { ok: false, reason: 'not-utf8' }
  }
}

/** True for a plain object -- not an array, not null, not a class instance dressed up as one. */
export function isPlainObject(value) {
  if (value === null || typeof value !== 'object' || Array.isArray(value)) return false
  const prototype = Object.getPrototypeOf(value)
  return prototype === Object.prototype || prototype === null
}
