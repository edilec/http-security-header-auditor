/**
 * The two header values this build understands structurally:
 * `Content-Security-Policy` and `Strict-Transport-Security`.
 *
 * Everything else is compared as an opaque string against the values the policy
 * declares, which is honest about what this package knows. A parser that half
 * understands `Permissions-Policy` and reports a verdict anyway is worse than
 * no parser at all, because its verdict looks like the others.
 *
 * Two bounds matter here and both are enforced by the caller's limits, not by a
 * timer around a call. Nothing in this module compiles a regular expression
 * from input -- a policy string is split on ASCII delimiters and walked once --
 * and the caller refuses a header value longer than `maxHeaderValueLength`
 * before this module ever sees it. A bound you cannot enforce is not a bound,
 * and a time check around a regular expression is not an enforcement: the
 * engine does not yield.
 */

import { asciiLower, byCodeUnit, excerpt } from './text.mjs'

/**
 * Directives whose value is a serialized source list, and which this build
 * therefore analyses for contradictions.
 *
 * Kept apart from the rest on purpose. `sandbox` takes sandboxing flags,
 * `report-uri` takes URIs, `trusted-types` takes policy names, and
 * `upgrade-insecure-requests` takes nothing at all. Running source-list
 * analysis over any of those would invent contradictions that are not there --
 * `sandbox allow-none` is not a source list with a keyword in it -- and a false
 * finding in a security report costs more than a missing one.
 */
export const SOURCE_LIST_DIRECTIVES = Object.freeze([
  'base-uri',
  'child-src',
  'connect-src',
  'default-src',
  'fenced-frame-src',
  'font-src',
  'form-action',
  'frame-ancestors',
  'frame-src',
  'img-src',
  'manifest-src',
  'media-src',
  'navigate-to',
  'object-src',
  'prefetch-src',
  'script-src',
  'script-src-attr',
  'script-src-elem',
  'style-src',
  'style-src-attr',
  'style-src-elem',
  'worker-src',
])

/** Directives this build recognises but does not analyse as a source list. */
export const OTHER_DIRECTIVES = Object.freeze([
  'block-all-mixed-content',
  'plugin-types',
  'referrer',
  'report-to',
  'report-uri',
  'require-trusted-types-for',
  'sandbox',
  'trusted-types',
  'upgrade-insecure-requests',
])

/** Every directive name this build knows, ordered by code unit. */
export const KNOWN_DIRECTIVES = Object.freeze(
  [...SOURCE_LIST_DIRECTIVES, ...OTHER_DIRECTIVES].sort(byCodeUnit),
)

const SOURCE_LIST_SET = new Set(SOURCE_LIST_DIRECTIVES)
const KNOWN_SET = new Set(KNOWN_DIRECTIVES)

/** A directive name, as the CSP grammar spells one. */
const DIRECTIVE_NAME = /^[A-Za-z0-9-]+$/

const HASH_PREFIXES = Object.freeze(["'sha256-", "'sha384-", "'sha512-"])

/**
 * Classify one source expression.
 *
 * `keyword` covers the quoted keywords whose meaning this build knows,
 * `nonce` and `hash` cover the two that carry entropy, `wildcard` is a bare
 * `*`, and `host` is everything else -- a scheme, a host, a path. The
 * classification is what the contradiction rules are written against, so it is
 * kept small and explicit rather than inferred from punctuation.
 */
export function classifySource(source) {
  const folded = asciiLower(source)
  if (folded === '*') return 'wildcard'
  if (folded === "'none'") return 'none'
  if (folded.startsWith("'nonce-")) return 'nonce'
  if (HASH_PREFIXES.some((prefix) => folded.startsWith(prefix))) return 'hash'
  if (folded.startsWith("'") ) return 'keyword'
  return 'host'
}

/**
 * Render a source for a report without reproducing entropy.
 *
 * A nonce is not a credential -- the browser receives it in the clear -- but it
 * is a per-response random value, and echoing it makes two runs over two
 * captures of the same route produce different reports for no reason a reader
 * can act on. The class is what the finding is about; the bytes are not.
 */
export function redactSource(source) {
  const kind = classifySource(source)
  if (kind === 'nonce') return "'nonce-...'"
  if (kind === 'hash') return `${asciiLower(source).slice(0, 8)}...'`
  return excerpt(source, 60)
}

/**
 * Parse a serialized CSP.
 *
 * Returns `{ ok: false, reason, limit, count }` when a declared bound was
 * reached: the policy is then not parsed at all, rather than parsed in part and
 * reported as if the part were the whole. A prefix of a security policy is not
 * a security policy.
 */
export function parseCsp(value, limits) {
  const segments = value.split(';')
  if (segments.length > limits.maxCspDirectives) {
    return { ok: false, reason: 'too-many-directives', limit: limits.maxCspDirectives, count: segments.length }
  }

  const directives = []
  const seen = new Map()
  const issues = []

  for (let index = 0; index < segments.length; index += 1) {
    const tokens = segments[index].split(/[ \t]+/).filter((token) => token !== '')
    if (tokens.length === 0) continue

    const rawName = tokens[0]
    const name = asciiLower(rawName)
    const sources = tokens.slice(1)

    if (!DIRECTIVE_NAME.test(rawName)) {
      issues.push({ kind: 'directive-malformed', directive: excerpt(rawName, 60), index })
      continue
    }
    if (sources.length > limits.maxCspSources) {
      return { ok: false, reason: 'too-many-sources', limit: limits.maxCspSources, count: sources.length, directive: name }
    }

    if (seen.has(name)) {
      // The browser keeps the first occurrence and ignores this one, so what the
      // author wrote is not what runs. That is a contradiction inside one
      // policy string, which is exactly what this tool exists to explain.
      issues.push({ kind: 'directive-duplicate', directive: name, index, firstIndex: seen.get(name) })
      continue
    }
    seen.set(name, index)

    const kind = SOURCE_LIST_SET.has(name) ? 'source-list' : 'other'
    if (!KNOWN_SET.has(name)) issues.push({ kind: 'directive-unknown', directive: name, index })

    directives.push({ name, sources, kind, index })
    if (kind === 'source-list') analyseSourceList(issues, name, sources, index)
  }

  return { ok: true, directives, issues }
}

/**
 * The contradiction rules, written against one source list.
 *
 * Each one describes a policy that says two things at once, where the browser
 * resolves the disagreement in a way the author probably did not intend. None
 * of them is a guess about intent: each is a statement about what the CSP
 * specification says will happen.
 */
function analyseSourceList(issues, name, sources, index) {
  const classes = sources.map((source) => classifySource(source))

  const seen = new Set()
  for (let position = 0; position < sources.length; position += 1) {
    const folded = asciiLower(sources[position])
    if (seen.has(folded)) {
      issues.push({ kind: 'source-duplicate', directive: name, index, source: redactSource(sources[position]) })
      continue
    }
    seen.add(folded)
  }

  // `'none'` means "no source is allowed", and the grammar permits it only as
  // the sole entry. Beside anything else the policy both allows and forbids the
  // same set, and the browser's reading is not the one a reader of the string
  // would expect.
  if (classes.includes('none') && sources.length > 1) {
    issues.push({
      kind: 'none-with-sources',
      directive: name,
      index,
      detail: sources
        .filter((source) => classifySource(source) !== 'none')
        .map((source) => redactSource(source))
        .sort(byCodeUnit),
    })
  }

  // A nonce or a hash disables `'unsafe-inline'` in every browser that
  // implements CSP Level 2 or later, and leaves it in force in one that does
  // not. The policy therefore means two different things depending on who reads
  // it, which is the definition of a contradictory directive.
  if (classes.includes('keyword') && classes.some((kind) => kind === 'nonce' || kind === 'hash')) {
    const hasUnsafeInline = sources.some((source) => asciiLower(source) === "'unsafe-inline'")
    if (hasUnsafeInline) {
      issues.push({
        kind: 'unsafe-inline-with-nonce',
        directive: name,
        index,
        detail: classes.includes('nonce') ? 'a nonce' : 'a hash',
      })
    }
  }

  // `*` already matches every host and scheme this directive can allow, so
  // every host listed beside it is dead text. A reviewer reading the list sees
  // an allow-list; the browser sees `*`.
  if (classes.includes('wildcard')) {
    const shadowed = sources.filter((source) => classifySource(source) === 'host')
    if (shadowed.length > 0) {
      issues.push({
        kind: 'wildcard-with-sources',
        directive: name,
        index,
        detail: shadowed.map((source) => redactSource(source)).sort(byCodeUnit),
      })
    }
  }
}

/**
 * Parse a `Strict-Transport-Security` value.
 *
 * `max-age` is the only directive that carries a value, and a value the grammar
 * does not allow is reported rather than coerced: `max-age=1e7` is not seven
 * digits to a browser, and reading it as ten million would report a policy
 * nobody deployed.
 */
export function parseHsts(value) {
  const issues = []
  const parsed = { maxAge: null, includeSubDomains: false, preload: false }
  const seen = new Set()

  for (const segment of value.split(';')) {
    const trimmed = segment.trim()
    if (trimmed === '') continue
    const equals = trimmed.indexOf('=')
    const name = asciiLower(equals === -1 ? trimmed : trimmed.slice(0, equals)).trim()
    const raw = equals === -1 ? null : trimmed.slice(equals + 1).trim().replace(/^"(.*)"$/, '$1')

    if (seen.has(name)) {
      issues.push({ kind: 'hsts-directive-duplicate', directive: excerpt(name, 40) })
      continue
    }
    seen.add(name)

    if (name === 'max-age') {
      if (raw === null || !/^\d{1,15}$/.test(raw)) {
        issues.push({ kind: 'hsts-max-age-malformed' })
        continue
      }
      parsed.maxAge = Number(raw)
    } else if (name === 'includesubdomains') {
      parsed.includeSubDomains = true
    } else if (name === 'preload') {
      parsed.preload = true
    } else {
      issues.push({ kind: 'hsts-directive-unknown', directive: excerpt(name, 40) })
    }
  }

  return { parsed, issues }
}
