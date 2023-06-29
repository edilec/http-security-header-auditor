/**
 * http-security-header-auditor -- evaluate captured HTTP response header fields
 * against a declared policy and its route exceptions, and explain the fields
 * that are missing and the directives that contradict one another.
 *
 * This package talks to nobody. It opens no socket, resolves no host, and
 * discovers no endpoint: the capture is a file somebody exported, and every
 * conclusion in the report is a conclusion about that file. The input schema has
 * nowhere to put an address, which is the structural half of the same promise --
 * a route is an opaque name, not a URL, so there is nothing here for a fetch to
 * take even if one were added. `README.md` and `docs/header-rules.md` say in
 * their own words what that does and does not establish.
 *
 * Three properties are load-bearing and are pinned by behaviour rather than by
 * declaration:
 *
 * - **Report-only enforces nothing.** A route carrying
 *   `Content-Security-Policy-Report-Only` and no `Content-Security-Policy` has
 *   no policy in force, is never counted as having one, and raises a rule of its
 *   own that says why.
 * - **A waiver excuses a known fact.** Route exceptions waive verdicts about a
 *   response. They never waive a gap in the evidence, so a capture this build
 *   could not read stays `incomplete` however many waivers the policy declares.
 * - **Order is by code unit.** Field names are RFC 9110 tokens, so `-` and `_`
 *   both occur and collate differently from their code points; a locale-aware
 *   comparison would list a route's fields differently on a different machine.
 */

import { readFile, realpath, stat } from 'node:fs/promises'
import { dirname, isAbsolute, normalize, resolve, sep } from 'node:path'
import { performance } from 'node:perf_hooks'

import { compileCapture, compilePolicy } from './documents.mjs'
import { createEvaluationState, evaluateRoutes } from './evaluate.mjs'
import { createFinding } from './rules.mjs'
import {
  byCodeUnit,
  decodeUtf8,
  excerpt,
  hasForbiddenCharacter,
  isCalendarDate,
  isPlainObject,
  parseFailureDetail,
} from './text.mjs'

export const TOOL_ID = 'http-security-header-auditor'
export const REPORT_SCHEMA_VERSION = '1'

export const DEFAULT_POLICY_NAME = 'policy.json'
export const DEFAULT_CAPTURE_NAME = 'capture.json'

/**
 * Limits, each enforced and each reported by name when it is reached.
 *
 * Exceeding one is never a silent truncation: it produces a finding that names
 * the limit and marks the run `incomplete`, because a partial walk is not
 * evidence that the part nobody walked was fine.
 *
 * `maxHeaderValueLength` is the bound that matters most and it is the one that
 * is genuinely enforceable. Nothing in this package compiles a regular
 * expression from input, and the two structural parsers split on ASCII
 * delimiters and walk their input once, so the work is linear in a length this
 * limit caps *before* the parser runs. A time check wrapped around a regular
 * expression would not be a bound at all: the engine does not yield, and two
 * tools in this catalog ran for seconds under declared millisecond budgets
 * because of exactly that mistake.
 */
export const DEFAULT_LIMITS = Object.freeze({
  maxCspDirectives: 50,
  maxCspSources: 100,
  maxExceptions: 200,
  maxFileBytes: 5242880,
  maxFindings: 1000,
  maxHeaderValueLength: 8192,
  maxHeadersPerRoute: 100,
  maxRequirements: 100,
  maxRoutes: 500,
  maxRuntimeMs: 10000,
})

/** A caller may lower a limit, never raise it past these caps. */
export const HARD_LIMITS = Object.freeze({
  maxCspDirectives: 500,
  maxCspSources: 2000,
  maxExceptions: 5000,
  maxFileBytes: 67108864,
  maxFindings: 20000,
  maxHeaderValueLength: 131072,
  maxHeadersPerRoute: 2000,
  maxRequirements: 2000,
  maxRoutes: 20000,
  maxRuntimeMs: 600000,
})

const MAX_NAME_LENGTH = 200

/**
 * The most field checks one report will hold, and the reason it is a product.
 *
 * Every other limit here bounds one dimension, and each one of them is enforced
 * exactly as documented. The size of a report is not one dimension: it is
 * `maxRoutes` multiplied by `maxRequirements`, because every route row lists the
 * required fields that route was missing. At the published caps that product is
 * forty million entries, and a run at those caps built a report that
 * `JSON.stringify` refused -- `RangeError: Invalid string length`, an empty
 * stdout, and an exit code that says the capture was audited and failed. Nothing
 * was audited and nothing failed.
 *
 * So the product is capped too, and it is capped in `validateLimits` rather than
 * mid-run: a configuration this build cannot carry to a report has no subject
 * yet, so it is refused before any evidence is read, the way an unknown limit
 * key and an out-of-range value already are. That is a refusal to start, not a
 * truncation -- nothing is audited and nothing is claimed.
 *
 * The number is measured, not guessed. At five million checks the worst report
 * this shape can produce is 137 MB of stdout and 927 MB of resident memory in
 * 6.3 s, and `JSON.stringify` gives up somewhere past twenty million. The
 * default limits ask for fifty thousand.
 */
export const MAX_FIELD_CHECKS = 5000000

const ALLOWED_OPTIONS = Object.freeze(['asOf', 'capture', 'clock', 'limits', 'policy', 'root'])

/** Raised when the run passes its time budget; turned into a finding by the caller. */
export class TimeBudgetExceeded extends Error {}

/**
 * Validate limit overrides.
 *
 * An unknown key throws rather than being ignored. A documented limit that a
 * typo silently disables is a limit that is not enforced, and the CLI turns
 * this throw into a configuration error with an empty stdout.
 */
export function validateLimits(overrides = {}) {
  if (!isPlainObject(overrides)) throw new TypeError('limits must be an object')
  const limits = { ...DEFAULT_LIMITS }
  for (const key of Object.keys(overrides).sort(byCodeUnit)) {
    if (!Object.hasOwn(DEFAULT_LIMITS, key)) {
      throw new TypeError(`Unknown limit "${excerpt(key, 60)}"; known limits are ${Object.keys(DEFAULT_LIMITS).sort(byCodeUnit).join(', ')}`)
    }
    const value = overrides[key]
    const cap = HARD_LIMITS[key]
    if (!Number.isInteger(value) || value < 1 || value > cap) {
      throw new TypeError(`limits.${key} must be an integer between 1 and ${cap}`)
    }
    limits[key] = value
  }
  const checks = limits.maxRoutes * limits.maxRequirements
  if (checks > MAX_FIELD_CHECKS) {
    throw new TypeError(
      `limits.maxRoutes (${limits.maxRoutes}) times limits.maxRequirements (${limits.maxRequirements}) is ${checks} field check(s), ` +
      `above the ${MAX_FIELD_CHECKS} this build will hold in one report; lower one of them.`,
    )
  }
  return Object.freeze(limits)
}

/**
 * True when `candidate` is the real root itself or lies beneath it.
 *
 * Both sides must already be real paths. Comparing a real root against a path
 * that has not been resolved refuses legitimate files whenever the root is
 * reached through a symbolic link -- a `/var` that is really `/private/var` is
 * enough -- and a false refusal is a defect too.
 */
export function isInside(root, candidate) {
  return candidate === root || candidate.startsWith(root.endsWith(sep) ? root : root + sep)
}

/**
 * A file name given on the command line, checked as configuration.
 *
 * Absolute paths and `..` segments are refused here, before any evidence is
 * gathered, because naming a file outside the declared root is a usage error
 * rather than a fact about the subject. This is emphatically *not* the
 * confinement: a symbolic link planted inside the root passes every check in
 * this function, and `resolveInput` is what catches it by resolving the real
 * path of both sides.
 */
function validateName(name, flag) {
  if (typeof name !== 'string' || name.length === 0 || name.length > MAX_NAME_LENGTH) {
    throw new TypeError(`${flag} must be a relative file name of 1-${MAX_NAME_LENGTH} characters`)
  }
  if (hasForbiddenCharacter(name)) {
    throw new TypeError(`${flag} must not contain a control, separator or bidi character`)
  }
  if (isAbsolute(name)) throw new TypeError(`${flag} must be relative to --root, not an absolute path`)
  const parts = normalize(name).split(/[\\/]/)
  if (parts.includes('..')) throw new TypeError(`${flag} must not step outside --root with ".."`)
  return name
}

/**
 * The findings, bounded as they arrive.
 *
 * Bounding at report-build time is not a bound at all: every row still has to
 * exist, and be turned into a finding object, and be sorted, before the slice
 * that drops it runs. At limits this package publishes as legal -- 20000 routes
 * against 2000 required fields, both files well under `maxFileBytes` -- that is
 * forty million rows, and the process died of heap exhaustion with an empty
 * stdout and an exit code of 134: outside the documented 0/1/2 contract, with
 * no finding naming any limit, which is the one outcome a limit exists to
 * prevent. `maxRuntimeMs` could not save it either, because the collapse is in
 * report construction after the loop the budget guards.
 *
 * So the cap is applied here, on arrival. Rows past it are counted and
 * discarded, and `buildReport` turns that count into the `too-many-findings`
 * finding that names the limit and marks the run incomplete. The memory a run
 * needs for findings is now bounded by `maxFindings`, whatever the documents
 * could raise.
 */
class FindingSink {
  constructor(maxFindings) {
    if (!Number.isInteger(maxFindings) || maxFindings < 1) throw new TypeError('maxFindings must be a positive integer')
    this.rows = []
    this.limit = maxFindings
    this.dropped = 0
  }

  add(row) {
    if (this.rows.length >= this.limit) {
      this.dropped += 1
      return
    }
    this.rows.push({ pointer: '', ...row })
  }
}

/**
 * The documented sort key: `location.file`, `location.pointer`, `ruleId`,
 * `message`.
 *
 * The message is part of the key because several rules anchor more than one
 * finding at the same pointer on purpose -- two required fields are both
 * missing from the same route, two directives in one policy string each
 * contradict themselves -- so the pointer alone does not separate them. No two
 * findings share all four components, and `sort` is stable, so even a tie would
 * preserve emission order, which is itself fixed by the documents.
 */
export function compareFindings(a, b) {
  return (
    byCodeUnit(a.location.file, b.location.file) ||
    byCodeUnit(a.location.pointer, b.location.pointer) ||
    byCodeUnit(a.ruleId, b.ruleId) ||
    byCodeUnit(a.message, b.message)
  )
}

function buildReport(sink, state, limits, files) {
  let findings = sink.rows.map((row) => createFinding(row)).sort(compareFindings)
  let truncated = false

  if (sink.dropped > 0) {
    // One kept row makes way for the finding that names the limit, so a
    // truncated report is exactly `maxFindings` long and says so. `dropped`
    // counts every row the sink refused, which is the honest total even though
    // those rows were never built.
    const dropped = sink.dropped + 1
    findings = findings.slice(0, limits.maxFindings - 1)
    findings.push(createFinding({
      file: files.capture,
      pointer: '',
      ruleId: 'too-many-findings',
      message: `The run produced more findings than the maxFindings limit of ${limits.maxFindings}; ${dropped} were not reported and this report is partial.`,
      suggestion: 'Raise --max-findings, or narrow the inputs.',
    }))
    findings.sort(compareFindings)
    truncated = true
  }

  let errors = 0
  let warnings = 0
  for (const finding of findings) {
    if (finding.severity === 'error') errors += 1
    else if (finding.severity === 'warning') warnings += 1
  }

  const status = state.incomplete || truncated ? 'incomplete' : errors > 0 ? 'fail' : 'pass'
  return {
    schemaVersion: REPORT_SCHEMA_VERSION,
    tool: TOOL_ID,
    status,
    asOf: state.asOf,
    summary: {
      checked: state.checked,
      errors,
      warnings,
      routes: state.routes,
      evaluated: state.rows.length,
      unevaluated: state.routes - state.rows.length,
      undecided: state.undecidedPairs,
      requirements: state.requirements,
      forbidden: state.forbidden,
      exceptionsDeclared: state.exceptionsDeclared,
      exceptionsApplied: state.exceptionsApplied,
      exceptionsExpired: state.exceptionsExpired,
      routesFailing: state.routesFailing,
      routesUndecided: state.routesUndecided,
    },
    routes: state.rows,
    findings,
  }
}

/**
 * Resolve one declared input inside the declared root.
 *
 * Both sides are resolved to their real paths before they are compared.
 * Rejecting `..` lexically -- which `validateName` also does -- is not
 * confinement: a symbolic link planted inside the root points anywhere and
 * contains no `..` at all. Equally, comparing a real root against an unresolved
 * target refuses legitimate files, so the root is resolved too.
 */
async function resolveInput(realRoot, name) {
  const target = resolve(realRoot, name)
  try {
    const real = await realpath(target)
    if (!isInside(realRoot, real)) return { ok: false, reason: 'escapes' }
    return { ok: true, real }
  } catch (error) {
    if (error.code !== 'ENOENT' && error.code !== 'ELOOP') return { ok: false, reason: 'unreadable', code: error.code }
    // The entry may still exist as a link that resolves nowhere. Confine the
    // nearest existing ancestor first, so a symlinked parent directory cannot
    // decide where a "missing" file would have been read from.
    try {
      const realParent = await realpath(dirname(target))
      if (!isInside(realRoot, realParent)) return { ok: false, reason: 'escapes' }
    } catch {
      return { ok: false, reason: 'unreadable', code: error.code }
    }
    return { ok: false, reason: 'unreadable', code: error.code }
  }
}

/** Read one confined input and turn it into parsed JSON, or into the finding that says why not. */
async function loadJson(sink, file, real, limits) {
  let info
  try {
    info = await stat(real)
  } catch (error) {
    sink.add({ file, ruleId: 'input-unreadable', message: `${file} could not be inspected: ${error.code ?? 'unknown error'}.` })
    return null
  }
  if (!info.isFile()) {
    sink.add({ file, ruleId: 'input-unreadable', message: `${file} is not a regular file, so nothing was read from it.` })
    return null
  }
  if (info.size > limits.maxFileBytes) {
    sink.add({
      file,
      ruleId: 'input-too-large',
      message: `${file} is ${info.size} bytes, above the maxFileBytes limit of ${limits.maxFileBytes}; it was not read.`,
      suggestion: 'Raise --max-file-bytes, or split the input.',
    })
    return null
  }
  let bytes
  try {
    bytes = await readFile(real)
  } catch (error) {
    sink.add({ file, ruleId: 'input-unreadable', message: `${file} could not be read: ${error.code ?? 'unknown error'}.` })
    return null
  }
  const decoded = decodeUtf8(bytes)
  if (!decoded.ok) {
    sink.add({
      file,
      ruleId: 'input-not-utf8',
      message: `${file} is not valid UTF-8, so it was not parsed. Whether a file decodes is the decoder's decision, never an inference drawn from the decoded text.`,
      suggestion: 'Re-encode the file as UTF-8.',
    })
    return null
  }
  try {
    return { value: JSON.parse(decoded.text) }
  } catch (error) {
    sink.add({
      file,
      ruleId: 'input-not-json',
      message: `${file} is not valid JSON: ${parseFailureDetail(error)}`,
      suggestion: 'Validate the file with a JSON parser before re-running.',
    })
    return null
  }
}

/**
 * Audit a capture against a policy.
 *
 * @param {object} options
 * @param {string} options.root Directory holding the two documents.
 * @param {string} [options.policy] Policy document, relative to the root.
 * @param {string} [options.capture] Capture document, relative to the root.
 * @param {string} [options.asOf] Calendar date, `YYYY-MM-DD`, that exception
 *   expiries are compared against. Omitted, no expiry can be decided: every
 *   waiver is withheld and the run is `incomplete`, which is the honest
 *   direction to fail in.
 * @param {object} [options.limits] Limit overrides; an unknown key throws.
 * @param {Function} [options.clock] Monotonic millisecond source for the time
 *   budget. Injected so a test can drive the budget without waiting, and so
 *   that nothing in this package reads a wall clock.
 * @returns {Promise<object>} the report.
 */
export async function auditHeaders(options = {}) {
  if (!isPlainObject(options)) throw new TypeError('options must be an object')
  for (const key of Object.keys(options).sort(byCodeUnit)) {
    if (!ALLOWED_OPTIONS.includes(key)) {
      throw new TypeError(`Unknown option "${excerpt(key, 60)}"; known options are ${ALLOWED_OPTIONS.join(', ')}`)
    }
  }
  const limits = validateLimits(options.limits ?? {})
  if (typeof options.root !== 'string' || options.root.length === 0) throw new TypeError('root must be a non-empty string')
  if (options.clock !== undefined && typeof options.clock !== 'function') throw new TypeError('clock must be a function returning milliseconds')
  if (options.asOf !== undefined && options.asOf !== null && !isCalendarDate(options.asOf)) {
    throw new TypeError('asOf must be a calendar date written YYYY-MM-DD')
  }
  const asOf = options.asOf ?? null

  const files = {
    policy: validateName(options.policy ?? DEFAULT_POLICY_NAME, '--policy'),
    capture: validateName(options.capture ?? DEFAULT_CAPTURE_NAME, '--capture'),
  }

  let realRoot
  try {
    realRoot = await realpath(options.root)
  } catch (error) {
    throw new Error(`--root could not be resolved: ${error.code ?? 'unknown error'}`)
  }
  let rootInfo
  try {
    rootInfo = await stat(realRoot)
  } catch (error) {
    throw new Error(`--root could not be inspected: ${error.code ?? 'unknown error'}`)
  }
  if (!rootInfo.isDirectory()) throw new Error('--root must be a directory')

  const clock = options.clock ?? (() => performance.now())
  const started = clock()
  const budget = {
    check() {
      if (clock() - started > limits.maxRuntimeMs) throw new TimeBudgetExceeded()
    },
  }

  const sink = new FindingSink(limits.maxFindings)
  const state = createEvaluationState()
  state.asOf = asOf
  state.routes = 0
  state.requirements = 0
  state.forbidden = 0
  state.exceptionsDeclared = 0

  const parsed = {}
  for (const kind of ['capture', 'policy']) {
    const name = files[kind]
    const located = await resolveInput(realRoot, name)
    if (!located.ok) {
      // (1) An input that could not be reached is missing evidence, not a
      // verdict about it.
      state.incomplete = true
      if (located.reason === 'escapes') {
        sink.add({
          file: name,
          ruleId: 'path-escapes-root',
          message: `${name} resolves outside --root, so it was refused unread.`,
          suggestion: 'Keep both documents inside the declared root; a symbolic link out of the tree is refused.',
        })
      } else {
        sink.add({
          file: name,
          ruleId: 'input-unreadable',
          message: `${name} could not be resolved inside --root: ${located.code ?? 'unknown error'}.`,
          suggestion: 'Check the file name and its permissions.',
        })
      }
      parsed[kind] = null
      continue
    }
    const loaded = await loadJson(sink, name, located.real, limits)
    // (2) Unreadable, undecodable or unparseable bytes are missing evidence too.
    if (loaded === null) state.incomplete = true
    parsed[kind] = loaded
  }

  const policy = parsed.policy === null ? null : compilePolicy(sink, files.policy, parsed.policy.value, limits)
  const capture = parsed.capture === null ? null : compileCapture(sink, files.capture, parsed.capture.value, limits)

  // (3) A document whose shape, version or size this build cannot take is a
  // document nothing was learned from.
  if (parsed.policy !== null && policy === null) state.incomplete = true
  if (parsed.capture !== null && capture === null) state.incomplete = true

  if (policy !== null) {
    state.requirements = policy.required.length
    state.forbidden = policy.forbidden.length
    state.exceptionsDeclared = policy.declaredExceptions
    // (4) An entry that did not compile was not compared against anything.
    // Reporting `fail` here would claim the whole policy was read when part of
    // it was refused.
    const compiled = policy.required.length + policy.forbidden.length + policy.exceptions.length
    const declared = policy.declaredRequired + policy.declaredForbidden + policy.declaredExceptions
    if (compiled !== declared) state.incomplete = true
  }
  if (capture !== null) {
    state.routes = capture.routes.length
    // (5) A route that did not compile was not audited.
    if (capture.routes.length !== capture.declaredRoutes) state.incomplete = true
  }

  if (policy !== null && capture !== null) {
    let aborted = false
    try {
      evaluateRoutes(sink, files, policy, capture, { asOf, limits }, budget, state)
    } catch (error) {
      if (!(error instanceof TimeBudgetExceeded)) throw error
      aborted = true
      sink.add({
        file: files.capture,
        pointer: '/routes',
        ruleId: 'time-budget-exceeded',
        message: `The audit passed the maxRuntimeMs budget of ${limits.maxRuntimeMs} and stopped; the routes below are the ones that were evaluated in full.`,
        suggestion: 'Raise --max-runtime-ms, or split the capture.',
      })
    }

    /**
     * (6) The budget re-checked *after* the loop, which is the only thing that
     * makes an aborted run `incomplete`.
     *
     * Deliberately not set in the `catch` above. A flag set where the failure is
     * noticed backstops itself: delete it and the rule that fired there still
     * makes the report non-green, so no test can tell. Set here instead, from
     * the count of rows that actually exist, it is load-bearing -- remove it and
     * an aborted run reports `fail` with an exit code of 1, and
     * `test/limits.test.mjs` says so.
     *
     * A run that says "unknown" is useless; a run that says "confirmed" when it
     * is not is harmful. Every route the loop was responsible for and did not
     * reach is downgraded here, after the loop, exactly because the loop cannot
     * be trusted to have finished.
     */
    if (state.rows.length !== capture.routes.length) state.incomplete = true
    if (aborted && state.rows.length === capture.routes.length) state.incomplete = true

    /**
     * (7) The vacuous pass, refused explicitly.
     *
     * Two documents that both compile, with nothing left to compare, would
     * otherwise report `pass` with `checked: 0` -- green on no evidence at all.
     * This is the only thing standing between that input and a green build, so
     * it is an error, it marks the run incomplete, and `test/incomplete.test.mjs`
     * fails if either half is removed.
     */
    if (state.checked === 0) {
      state.incomplete = true
      sink.add({
        file: files.policy,
        pointer: '/required',
        ruleId: 'no-checks-performed',
        message: `The run compared ${state.routes} route(s) against ${state.requirements} required and ${state.forbidden} forbidden field(s) and decided nothing, so it has no evidence to be green on.`,
        suggestion: 'Declare the fields this policy is about, capture the routes it applies to, and fix whatever stopped the pairs that are there from being decided.',
      })
    }
  }

  return buildReport(sink, state, limits, files)
}

/** stdout carries this and nothing else, so it can be piped straight into a parser. */
export function serializeReport(report) {
  return JSON.stringify(report, null, 2)
}

/** 0 completed and passed, 1 completed and failed, 2 the run could not be completed. */
export function exitCodeFor(report) {
  if (report.status === 'incomplete') return 2
  return report.status === 'fail' ? 1 : 0
}

const SEVERITY_WIDTH = 7

/** The human summary. It goes to stderr; stdout is the JSON report alone. */
export function formatReport(report, extra = {}) {
  const { summary } = report
  const lines = [
    `policy ${excerpt(extra.policy ?? DEFAULT_POLICY_NAME, 80)}: ${summary.requirements} required, ${summary.forbidden} forbidden, ${summary.exceptionsDeclared} exception(s).`,
    `capture ${excerpt(extra.capture ?? DEFAULT_CAPTURE_NAME, 80)}: ${summary.evaluated} of ${summary.routes} route(s) evaluated, ${summary.routesFailing} failing, ${summary.routesUndecided} undecided.`,
    `${summary.checked} field check(s) decided, ${summary.undecided} left undecided, as of ${report.asOf ?? 'no date given'}. status ${report.status}.`,
  ]
  for (const finding of report.findings) {
    lines.push(
      `${finding.severity.toUpperCase().padEnd(SEVERITY_WIDTH)} ` +
      `${finding.location.file}${finding.location.pointer} ${finding.ruleId} ${finding.message}`,
    )
  }
  return `${lines.join('\n')}\n`
}

export { RULE_SEVERITY, WAIVABLE_RULES, createFinding, isWaivable, severityOf } from './rules.mjs'
export {
  CAPTURE_DOCUMENT_KEYS, CSP_HEADER, CSP_REPORT_ONLY_HEADER, DOCUMENT_SCHEMA_VERSION,
  EXCEPTION_KEYS, FORBIDDEN_KEYS, HEADER_KEYS, HSTS_HEADER, POLICY_DOCUMENT_KEYS,
  REQUIREMENT_KEYS, ROUTE_KEYS, compileCapture, compilePolicy,
} from './documents.mjs'
export { KNOWN_DIRECTIVES, OTHER_DIRECTIVES, SOURCE_LIST_DIRECTIVES, classifySource, parseCsp, parseHsts, redactSource } from './directives.mjs'
export {
  EXCERPT_LIMIT, MAX_DESCRIPTION_LENGTH, MAX_HEADER_NAME_LENGTH, MAX_IDENTIFIER_LENGTH,
  MAX_REASON_LENGTH, asciiLower, byCodeUnit, decodeUtf8, describeValue, excerpt,
  hasForbiddenCharacter, isCalendarDate, isHeaderName, isIdentifier, isPlainObject, looksLikePattern,
  parseFailureDetail,
} from './text.mjs'
