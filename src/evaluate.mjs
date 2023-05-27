/**
 * The evaluation: one captured route at a time, against the compiled policy.
 *
 * Two properties are load-bearing here and both are stated as code rather than
 * as prose in a README.
 *
 * **Report-only enforces nothing.** `Content-Security-Policy-Report-Only` and
 * `Content-Security-Policy` are two different fields, and only the second one
 * stops anything loading. A route carrying the first and not the second has no
 * content security policy in force, and this module says exactly that: the
 * presence check for `content-security-policy` looks the field up by its whole
 * name, so the report-only field can never satisfy it, and a separate rule
 * explains why a route that clearly *meant* to have a policy does not have one.
 *
 * **A waiver excuses a known fact, never an unknown one.** Route exceptions
 * waive the rules in `WAIVABLE_RULES` and nothing else. A field captured twice,
 * a value too long to parse, a policy string past the directive bound: those
 * are gaps in the evidence, they keep the run `incomplete` whatever the policy
 * declares, and no waiver reaches them.
 */

import { CSP_HEADER, CSP_REPORT_ONLY_HEADER, HSTS_HEADER } from './documents.mjs'
import { KNOWN_DIRECTIVES, parseCsp, parseHsts, redactSource } from './directives.mjs'
import { isWaivable, severityOf } from './rules.mjs'
import { asciiLower, byCodeUnit, excerpt } from './text.mjs'

const EVIDENCE_LIMIT = 120
const KNOWN_DIRECTIVE_SET = new Set(KNOWN_DIRECTIVES)

/** The key an exception is looked up by. Neither part can contain a space, so a space separates them. */
const waiverKey = (route, header) => `${route} ${header}`

/**
 * The mutable state one evaluation accumulates.
 *
 * Created by the caller rather than here, so that a run cut short by the time
 * budget leaves its partial counts and its partial rows in the caller's hands.
 * A thrown budget must not take the record of what *was* evaluated with it.
 */
export function createEvaluationState() {
  return {
    checked: 0,
    undecidedPairs: 0,
    exceptionsApplied: 0,
    exceptionsExpired: 0,
    exceptionsUndecidable: 0,
    routesFailing: 0,
    routesUndecided: 0,
    routesWaived: 0,
    incomplete: false,
    rows: [],
  }
}

function cspIssueFinding(issue, route, entry, file) {
  const where = `${entry.pointer}/value`
  const id = excerpt(route.id, 100)

  if (issue.kind === 'directive-malformed') {
    return {
      file,
      pointer: where,
      ruleId: 'csp-directive-malformed',
      message: `On route "${id}", segment ${issue.index} of the policy starts with "${issue.directive}", which is not a directive name; a browser discards the whole segment, so whatever it was meant to restrict is unrestricted.`,
      suggestion: 'A directive name is made of letters, digits and hyphens.',
    }
  }
  if (issue.kind === 'directive-duplicate') {
    return {
      file,
      pointer: where,
      ruleId: 'csp-directive-duplicate',
      message: `On route "${id}", the policy declares "${issue.directive}" twice, at segment ${issue.firstIndex} and segment ${issue.index}. A browser keeps the first and ignores the second, so the second one restricts nothing and what runs is not what the policy says.`,
      suggestion: 'Merge the two into one directive with the union of the sources you meant to allow.',
    }
  }
  if (issue.kind === 'directive-unknown') {
    return {
      file,
      pointer: where,
      ruleId: 'csp-directive-unknown',
      message: `On route "${id}", the policy declares "${issue.directive}", which this build does not know; it was recorded but not analysed, and no claim is made about what it allows.`,
      suggestion: 'Check the spelling; a browser ignores a directive it does not recognise.',
    }
  }
  if (issue.kind === 'source-duplicate') {
    return {
      file,
      pointer: where,
      ruleId: 'csp-source-duplicate',
      message: `On route "${id}", directive "${issue.directive}" lists ${issue.source} more than once; the repeat allows nothing extra and was counted once.`,
    }
  }
  if (issue.kind === 'none-with-sources') {
    return {
      file,
      pointer: where,
      ruleId: 'csp-none-with-sources',
      message: `On route "${id}", directive "${issue.directive}" lists 'none' beside ${issue.detail.length} other source(s), so the same directive both forbids everything and allows something. The grammar permits 'none' only on its own, and a browser resolves the disagreement by ignoring 'none'.`,
      evidence: issue.detail.join(' '),
      suggestion: `Remove 'none', or remove every other source from "${issue.directive}".`,
    }
  }
  if (issue.kind === 'unsafe-inline-with-nonce') {
    return {
      file,
      pointer: where,
      ruleId: 'csp-unsafe-inline-with-nonce',
      message: `On route "${id}", directive "${issue.directive}" lists 'unsafe-inline' beside ${issue.detail}. A browser that implements CSP Level 2 or later ignores 'unsafe-inline' whenever a nonce or hash is present, and an older one honours it, so this directive means two different things to two readers.`,
      suggestion: `Drop 'unsafe-inline' from "${issue.directive}" if the nonce is the control you rely on.`,
    }
  }
  if (issue.kind === 'wildcard-with-sources') {
    return {
      file,
      pointer: where,
      ruleId: 'csp-wildcard-shadows-sources',
      message: `On route "${id}", directive "${issue.directive}" lists * beside ${issue.detail.length} named source(s); * already matches all of them, so the list reads as an allow-list and behaves as no list at all.`,
      evidence: issue.detail.join(' '),
      suggestion: `Remove *, or remove the named sources from "${issue.directive}".`,
    }
  }
  throw new Error(`Unhandled CSP issue kind "${issue.kind}"`)
}

function hstsIssueFinding(issue, route, entry, file) {
  const where = `${entry.pointer}/value`
  const id = excerpt(route.id, 100)

  if (issue.kind === 'hsts-max-age-malformed') {
    return {
      file,
      pointer: where,
      ruleId: 'hsts-max-age-malformed',
      message: `On route "${id}", the Strict-Transport-Security max-age is not a plain sequence of digits, so no duration could be read from it and none was guessed.`,
      suggestion: 'Write max-age as a whole number of seconds, for example max-age=31536000.',
    }
  }
  if (issue.kind === 'hsts-directive-duplicate') {
    return {
      file,
      pointer: where,
      ruleId: 'hsts-directive-duplicate',
      message: `On route "${id}", the Strict-Transport-Security field declares "${issue.directive}" more than once; the repeat was ignored.`,
    }
  }
  if (issue.kind === 'hsts-directive-unknown') {
    return {
      file,
      pointer: where,
      ruleId: 'hsts-directive-unknown',
      message: `On route "${id}", the Strict-Transport-Security field declares "${issue.directive}", which is not one of max-age, includeSubDomains or preload; it was recorded but not analysed.`,
    }
  }
  throw new Error(`Unhandled HSTS issue kind "${issue.kind}"`)
}

/**
 * Check one present field against one requirement.
 *
 * Adds to `undecided` whenever the evidence does not support a verdict, which
 * is what stops an unreadable policy string being counted as a satisfied one.
 */
function checkRequirement(context, route, requirement, entry, parsedCsp, hsts, push, undecided) {
  const { files } = context
  const id = excerpt(route.id, 100)
  const header = requirement.header

  if (requirement.allowedValues !== null) {
    const folded = asciiLower(entry.value.trim())
    if (!requirement.allowedValues.includes(folded)) {
      push(header, {
        file: files.capture,
        pointer: `${entry.pointer}/value`,
        ruleId: 'header-value-unexpected',
        message: `On route "${id}", "${header}" carries a value ${files.policy} does not allow at ${requirement.pointer}; the allowed value(s) are ${requirement.allowedValues.join(', ')}.`,
        evidence: excerpt(entry.value, EVIDENCE_LIMIT),
      })
    }
  }

  if (header === CSP_HEADER && parsedCsp !== null) {
    const present = new Set(parsedCsp.directives.map((directive) => directive.name))

    if (requirement.requiredDirectives !== null) {
      for (const name of requirement.requiredDirectives) {
        if (present.has(name)) continue
        push(header, {
          file: files.capture,
          pointer: `${entry.pointer}/value`,
          ruleId: 'csp-directive-missing',
          message: `On route "${id}", the policy declares no "${name}" directive, which ${files.policy} requires at ${requirement.pointer}. A directive that is absent falls back to default-src where one applies, and to nothing where none does.`,
          suggestion: `Add "${name}" to the policy, or remove it from the requirement.`,
        })
      }
    }

    if (requirement.forbiddenSources !== null) {
      // A directive this build does not know may be a source list carrying one
      // of the forbidden sources, and this build did not look inside it. Saying
      // "none of the forbidden sources is present" would then be a claim about
      // evidence nobody obtained, so the field is left undecided instead.
      const unknown = parsedCsp.directives
        .filter((directive) => !KNOWN_DIRECTIVE_SET.has(directive.name))
        .map((directive) => directive.name)
        .sort(byCodeUnit)
      if (unknown.length > 0) {
        undecided.add(header)
        push(header, {
          file: files.capture,
          pointer: `${entry.pointer}/value`,
          ruleId: 'csp-analysis-incomplete',
          message: `On route "${id}", ${files.policy} forbids source(s) at ${requirement.pointer}, and the policy declares directive(s) ${unknown.join(', ')} that this build does not analyse; whether a forbidden source appears inside them was not determined, so this field is undecided rather than clean.`,
          suggestion: 'Remove the unrecognised directive, or check that directive by hand.',
        })
      } else {
        for (const directive of parsedCsp.directives) {
          if (directive.kind !== 'source-list') continue
          const seen = new Set()
          for (const source of directive.sources) {
            const folded = asciiLower(source)
            if (!requirement.forbiddenSources.includes(folded) || seen.has(folded)) continue
            seen.add(folded)
            push(header, {
              file: files.capture,
              pointer: `${entry.pointer}/value`,
              ruleId: 'csp-source-forbidden',
              message: `On route "${id}", directive "${directive.name}" allows ${redactSource(source)}, which ${files.policy} forbids at ${requirement.pointer}.`,
              suggestion: `Remove that source from "${directive.name}".`,
            })
          }
        }
      }
    }
  }

  if (header === HSTS_HEADER && hsts !== null) {
    if (requirement.minMaxAge !== null) {
      if (hsts.parsed.maxAge === null) {
        if (!hsts.malformed) {
          push(header, {
            file: files.capture,
            pointer: `${entry.pointer}/value`,
            ruleId: 'hsts-max-age-missing',
            message: `On route "${id}", Strict-Transport-Security declares no max-age, so the field asks the browser to remember nothing; ${files.policy} requires at least ${requirement.minMaxAge} seconds at ${requirement.pointer}.`,
            suggestion: `Add max-age=${requirement.minMaxAge} or longer.`,
          })
        }
      } else if (hsts.parsed.maxAge < requirement.minMaxAge) {
        push(header, {
          file: files.capture,
          pointer: `${entry.pointer}/value`,
          ruleId: 'hsts-max-age-too-short',
          message: `On route "${id}", Strict-Transport-Security declares max-age=${hsts.parsed.maxAge}, below the ${requirement.minMaxAge} seconds ${files.policy} requires at ${requirement.pointer}.`,
          suggestion: `Raise max-age to ${requirement.minMaxAge} or longer.`,
        })
      }
    }
    if (requirement.requireIncludeSubDomains === true && !hsts.parsed.includeSubDomains) {
      push(header, {
        file: files.capture,
        pointer: `${entry.pointer}/value`,
        ruleId: 'hsts-include-subdomains-missing',
        message: `On route "${id}", Strict-Transport-Security declares no includeSubDomains, which ${files.policy} requires at ${requirement.pointer}; subdomains are therefore not covered.`,
      })
    }
    if (requirement.requirePreload === true && !hsts.parsed.preload) {
      push(header, {
        file: files.capture,
        pointer: `${entry.pointer}/value`,
        ruleId: 'hsts-preload-missing',
        message: `On route "${id}", Strict-Transport-Security declares no preload token, which ${files.policy} requires at ${requirement.pointer}.`,
      })
    }
  }
}

/**
 * Evaluate one route. Returns the row that describes it.
 *
 * The route is atomic: the time budget is checked between routes and never
 * inside one, so a row exists only for a route that was evaluated from end to
 * end. A row is a claim, and a claim about a route nobody finished reading is
 * exactly the false positive this catalog keeps producing.
 */
function evaluateRoute(context, route) {
  const { sink, files, policy, options, state } = context
  const id = excerpt(route.id, 100)
  const pending = new Map()
  const undecided = new Set()
  let routeErrors = 0

  const push = (header, row) => {
    const list = pending.get(header)
    if (list === undefined) pending.set(header, [row])
    else list.push(row)
  }
  const emit = (row) => {
    sink.add(row)
    if (severityOf(row.ruleId) === 'error') routeErrors += 1
  }

  for (const [name, entries] of route.byName) {
    if (entries.length > 1) {
      undecided.add(name)
      push(name, {
        file: files.capture,
        pointer: entries[1].pointer,
        ruleId: 'header-duplicated',
        message: `Route "${id}" carries "${name}" ${entries.length} times with no single authoritative value; this build does not pick one, so nothing about this field was decided.`,
        suggestion: 'Re-export the capture with one entry per field, combining repeated values the way the field grammar says they combine.',
      })
    }
    if (entries.some((entry) => entry.problem !== null)) undecided.add(name)
  }

  const cspEntries = route.byName.get(CSP_HEADER)
  const reportOnlyEntries = route.byName.get(CSP_REPORT_ONLY_HEADER)
  const csp = { enforced: cspEntries !== undefined, reportOnly: reportOnlyEntries !== undefined, analysed: false, directives: [] }
  let parsedCsp = null

  if (cspEntries !== undefined && !undecided.has(CSP_HEADER)) {
    const result = parseCsp(cspEntries[0].value, options.limits)
    if (result.ok) {
      parsedCsp = result
      csp.analysed = true
      csp.directives = result.directives.map((directive) => directive.name).sort(byCodeUnit)
      for (const issue of result.issues) push(CSP_HEADER, cspIssueFinding(issue, route, cspEntries[0], files.capture))
    } else {
      undecided.add(CSP_HEADER)
      push(CSP_HEADER, {
        file: files.capture,
        pointer: `${cspEntries[0].pointer}/value`,
        ruleId: 'csp-unparseable',
        message: result.reason === 'too-many-directives'
          ? `On route "${id}", the policy declares ${result.count} segment(s), above the maxCspDirectives limit of ${result.limit}; it was not parsed, so nothing about it was decided.`
          : `On route "${id}", directive "${result.directive}" lists ${result.count} source(s), above the maxCspSources limit of ${result.limit}; the policy was not parsed, so nothing about it was decided.`,
        suggestion: 'Raise the limit if the policy is genuine, or shorten the policy.',
      })
    }
  }

  // The acceptance case, and the reason it needs a rule of its own: a
  // report-only policy is a diagnostic channel. The browser reports the
  // violation and then loads the resource anyway. A route carrying only that
  // field has no content security policy in force, and a reader skimming a
  // capture for the string "Content-Security-Policy" will conclude otherwise.
  if (csp.reportOnly && !csp.enforced) {
    push(CSP_HEADER, {
      file: files.capture,
      pointer: reportOnlyEntries[0].pointer,
      ruleId: 'csp-report-only-without-enforcement',
      message: `Route "${id}" carries ${CSP_REPORT_ONLY_HEADER} and no ${CSP_HEADER}. A report-only policy enforces nothing: the browser reports the violation and loads the resource anyway, so this route has no content security policy in force.`,
      suggestion: 'Send the same policy in the Content-Security-Policy field once the reports are clean, or declare a route exception with a reason and an expiry while the rollout runs.',
    })
  }

  const hstsEntries = route.byName.get(HSTS_HEADER)
  let hsts = null
  if (hstsEntries !== undefined && !undecided.has(HSTS_HEADER)) {
    const result = parseHsts(hstsEntries[0].value)
    hsts = { parsed: result.parsed, malformed: result.issues.some((issue) => issue.kind === 'hsts-max-age-malformed') }
    for (const issue of result.issues) push(HSTS_HEADER, hstsIssueFinding(issue, route, hstsEntries[0], files.capture))
  }

  for (const entry of policy.forbidden) {
    const present = route.byName.get(entry.header)
    state.checked += 1
    if (present === undefined) continue
    push(entry.header, {
      file: files.capture,
      pointer: present[0].pointer,
      ruleId: 'forbidden-header-present',
      message: `Route "${id}" carries "${entry.header}", which ${files.policy} forbids at ${entry.pointer}.`,
      ...(present[0].problem === null ? { evidence: excerpt(present[0].value, EVIDENCE_LIMIT) } : {}),
      suggestion: 'Stop sending the field, or remove it from the forbidden list.',
    })
  }

  const missing = []
  for (const requirement of policy.required) {
    const entries = route.byName.get(requirement.header)

    if (entries === undefined) {
      missing.push(requirement.header)
      state.checked += 1
      push(requirement.header, {
        file: files.capture,
        pointer: route.pointer,
        ruleId: 'required-header-missing',
        message: `Route "${id}" carries no "${requirement.header}" field, which ${files.policy} requires at ${requirement.pointer}.`,
        suggestion: `Send "${requirement.header}" on this route, or waive it with a route exception carrying a reason and an expiry.`,
      })
      continue
    }

    if (undecided.has(requirement.header)) {
      state.undecidedPairs += 1
      continue
    }

    checkRequirement(context, route, requirement, entries[0], parsedCsp, hsts, push, undecided)

    if (undecided.has(requirement.header)) state.undecidedPairs += 1
    else state.checked += 1
  }

  const waived = []
  const headers = [...pending.keys()].sort(byCodeUnit)
  for (const header of headers) {
    const rows = pending.get(header)
    const waivable = rows.filter((row) => isWaivable(row.ruleId))
    for (const row of rows) if (!isWaivable(row.ruleId)) emit(row)

    const exception = waivable.length === 0 ? undefined : context.exceptions.get(waiverKey(route.id, header))
    if (exception === undefined) {
      for (const row of waivable) emit(row)
      continue
    }
    context.used.add(waiverKey(route.id, header))

    if (options.asOf === null) {
      state.exceptionsUndecidable += 1
      state.incomplete = true
      emit({
        file: files.policy,
        pointer: exception.pointer,
        ruleId: 'exception-expiry-undecidable',
        message: `The waiver for route "${id}" and field "${header}" expires on ${exception.expires}, and this run was given no --as-of date to compare it against. An expiry nobody checked is not an expiry, so the waiver was not applied.`,
        suggestion: 'Re-run with --as-of YYYY-MM-DD.',
      })
      for (const row of waivable) emit(row)
      continue
    }

    if (exception.expires < options.asOf) {
      state.exceptionsExpired += 1
      emit({
        file: files.policy,
        pointer: `${exception.pointer}/expires`,
        ruleId: 'exception-expired',
        message: `The waiver for route "${id}" and field "${header}" expired on ${exception.expires}, before the --as-of date ${options.asOf}; it excuses nothing now, and the ${waivable.length} finding(s) it covered are reported.`,
        evidence: excerpt(exception.reason, EVIDENCE_LIMIT),
        suggestion: 'Fix the route, or renew the waiver with a fresh reason and expiry.',
      })
      for (const row of waivable) emit(row)
      continue
    }

    state.exceptionsApplied += 1
    waived.push(header)
    const ruleIds = [...new Set(waivable.map((row) => row.ruleId))].sort(byCodeUnit)
    emit({
      file: files.policy,
      pointer: exception.pointer,
      ruleId: 'exception-applied',
      message: `On route "${id}", a waiver for "${header}" holds until ${exception.expires} and excuses ${ruleIds.join(', ')}.`,
      evidence: excerpt(exception.reason, EVIDENCE_LIMIT),
    })
  }

  const undecidedList = [...undecided].sort(byCodeUnit)
  let verdict = 'pass'
  if (routeErrors > 0) verdict = 'fail'
  else if (waived.length > 0) verdict = 'waived'
  if (undecidedList.length > 0 || route.refusedHeaders > 0) verdict = 'undecided'

  if (verdict === 'undecided') {
    state.incomplete = true
    state.routesUndecided += 1
  } else if (verdict === 'fail') state.routesFailing += 1
  else if (verdict === 'waived') state.routesWaived += 1

  return {
    id: route.id,
    verdict,
    headers: [...route.byName.keys()].sort(byCodeUnit),
    missing: [...missing].sort(byCodeUnit),
    waived: waived.sort(byCodeUnit),
    undecided: undecidedList,
    csp,
  }
}

/**
 * Evaluate every compiled route against the compiled policy.
 *
 * The time budget is checked once per route, so a route is evaluated whole or
 * not at all, and the caller compares `rows.length` against the number of
 * compiled routes after the loop rather than trusting that the loop ran to the
 * end. A budget that can be exhausted inside a loop has to be re-checked after
 * it, because the alternative -- a break that falls through to the success
 * branch -- is how a tool in this catalog came to write "confirmed" about a
 * group it never finished comparing.
 */
export function evaluateRoutes(sink, files, policy, capture, options, budget, state) {
  const exceptions = new Map()
  for (const exception of policy.exceptions) exceptions.set(waiverKey(exception.route, exception.header), exception)

  const context = { sink, files, policy, options, state, exceptions, used: new Set() }

  for (const route of capture.routes) {
    budget.check()
    state.rows.push(evaluateRoute(context, route))
  }

  budget.check()

  for (const exception of policy.exceptions) {
    if (context.used.has(waiverKey(exception.route, exception.header))) continue
    if (!capture.byId.has(exception.route)) {
      sink.add({
        file: files.policy,
        pointer: `${exception.pointer}/route`,
        ruleId: 'exception-route-unknown',
        message: `The waiver at ${exception.pointer} names route "${excerpt(exception.route, 100)}", which ${files.capture} does not contain; it excused nothing in this run.`,
        suggestion: 'Remove the waiver, or capture the route it refers to.',
      })
      continue
    }
    sink.add({
      file: files.policy,
      pointer: exception.pointer,
      ruleId: 'exception-unused',
      message: `The waiver at ${exception.pointer} for route "${excerpt(exception.route, 100)}" and field "${exception.header}" excused nothing: that route and field raised no finding a waiver can cover.`,
      suggestion: 'Retire the waiver.',
    })
  }

  state.rows.sort((left, right) => byCodeUnit(left.id, right.id))
  return state
}
