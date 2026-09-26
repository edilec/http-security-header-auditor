/**
 * The rule catalog: one frozen severity table, one frozen waivable set, and the
 * single place a finding is built.
 *
 * Severity is the whole difference between a run that fails and one that
 * passes. Written as a literal at each construction site it drifts silently,
 * and demoting one of the error rules below turns "this route has no
 * Content-Security-Policy" into a green build with every test still passing.
 * Every finding takes its severity from here, and an unknown rule id throws.
 *
 * `test/severity-table.test.mjs` asserts this table against the documented
 * catalog in both directions. That is worth having and it is not the test: a
 * table, a catalog and a test's expected map are three declarations, and one
 * edit that changes all three leaves every assertion that compares them
 * satisfied -- including an assertion made inside a loop over that same map.
 * `test/severity-exit.test.mjs` and `test/severity-word.test.mjs` drive real
 * inputs through the real binary and pin the exit code, the error count and the
 * printed severity word with literal values instead.
 */

import { excerpt } from './text.mjs'

export const RULE_SEVERITY = Object.freeze({
  'csp-analysis-incomplete': 'error',
  'csp-directive-duplicate': 'error',
  'csp-directive-malformed': 'error',
  'csp-directive-missing': 'error',
  'csp-directive-unknown': 'warning',
  'csp-none-with-sources': 'error',
  'csp-report-only-without-enforcement': 'error',
  'csp-source-duplicate': 'warning',
  'csp-source-forbidden': 'error',
  'csp-unparseable': 'error',
  'csp-unsafe-inline-with-nonce': 'error',
  'csp-wildcard-shadows-sources': 'warning',
  'document-invalid': 'error',
  'exception-applied': 'info',
  'exception-expired': 'error',
  'exception-expiry-missing': 'error',
  'exception-expiry-undecidable': 'error',
  'exception-reason-missing': 'error',
  'exception-route-unknown': 'warning',
  'exception-unused': 'warning',
  'forbidden-header-present': 'error',
  'header-duplicated': 'error',
  'header-invalid': 'error',
  'header-value-control-character': 'error',
  'header-value-too-long': 'error',
  'header-value-unexpected': 'error',
  'hsts-directive-duplicate': 'error',
  'hsts-directive-unknown': 'warning',
  'hsts-include-subdomains-missing': 'error',
  'hsts-max-age-malformed': 'error',
  'hsts-max-age-missing': 'error',
  'hsts-max-age-too-short': 'error',
  'hsts-preload-missing': 'error',
  'identifier-invalid': 'error',
  'input-not-json': 'error',
  'input-not-utf8': 'error',
  'input-too-large': 'error',
  'input-unreadable': 'error',
  'no-checks-performed': 'error',
  'path-escapes-root': 'error',
  'pattern-unsupported': 'error',
  'policy-contradiction': 'error',
  'policy-invalid': 'error',
  'required-header-missing': 'error',
  'route-duplicate': 'error',
  'route-invalid': 'error',
  'schema-version-unsupported': 'error',
  'time-budget-exceeded': 'error',
  'too-many-exceptions': 'error',
  'too-many-findings': 'error',
  'too-many-headers': 'error',
  'too-many-requirements': 'error',
  'too-many-routes': 'error',
})

/**
 * The rules a route exception may waive: exactly those that are verdicts about
 * a response, and nothing that is a gap in the evidence.
 *
 * This boundary is the one that keeps waivers honest. A waiver says "we know
 * this route does not carry a Content-Security-Policy, here is why, and here is
 * when we stop accepting it" -- a statement somebody can review because the
 * fact being excused is known. It must never be able to say "we do not know
 * what this route carries, and that is fine", because nobody can review a
 * statement about something nobody read. So a field whose value was too long to
 * parse, a field captured twice with two values, a field value carrying a
 * control character, a policy string past the directive bound: none of those
 * can be excused by anybody, and every one of them keeps the run `incomplete`
 * however many waivers the policy declares.
 *
 * `test/exceptions.test.mjs` pins this behaviourally -- an exception covering
 * exactly such a route still exits 2 -- rather than by comparing this set
 * against another declaration of itself.
 */
export const WAIVABLE_RULES = Object.freeze([
  'csp-directive-duplicate',
  'csp-directive-malformed',
  'csp-directive-missing',
  'csp-directive-unknown',
  'csp-none-with-sources',
  'csp-report-only-without-enforcement',
  'csp-source-duplicate',
  'csp-source-forbidden',
  'csp-unsafe-inline-with-nonce',
  'csp-wildcard-shadows-sources',
  'forbidden-header-present',
  'header-value-unexpected',
  'hsts-directive-unknown',
  'hsts-include-subdomains-missing',
  'hsts-max-age-malformed',
  'hsts-max-age-missing',
  'hsts-max-age-too-short',
  'hsts-preload-missing',
  'required-header-missing',
])

const WAIVABLE_SET = new Set(WAIVABLE_RULES)

export function isWaivable(ruleId) {
  return WAIVABLE_SET.has(ruleId)
}

export function severityOf(ruleId) {
  const severity = RULE_SEVERITY[ruleId]
  if (severity === undefined) {
    throw new Error(`Rule "${ruleId}" is not in RULE_SEVERITY; add it to the table and to docs/header-rules.md.`)
  }
  return severity
}

export const MESSAGE_LIMIT = 400
export const SUGGESTION_LIMIT = 300
export const LOCATION_LIMIT = 200

/**
 * Build a finding, taking its severity from the one table.
 *
 * Every untrusted string is sanitised here -- file, pointer, message,
 * suggestion and evidence alike, not only the evidence field. A sibling tool
 * sanitised evidence carefully and left identifiers raw, so a record id holding
 * a newline forged an extra line in the human report.
 */
export function createFinding(row) {
  const finding = {
    ruleId: row.ruleId,
    severity: severityOf(row.ruleId),
    message: excerpt(row.message, MESSAGE_LIMIT),
    location: { file: excerpt(row.file, LOCATION_LIMIT), pointer: excerpt(row.pointer ?? '', LOCATION_LIMIT) },
  }
  if (row.evidence !== undefined && row.evidence !== '') finding.evidence = excerpt(row.evidence)
  if (row.suggestion !== undefined) finding.suggestion = excerpt(row.suggestion, SUGGESTION_LIMIT)
  return finding
}
