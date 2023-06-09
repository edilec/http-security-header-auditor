/**
 * The two input documents, compiled from parsed JSON into the shapes the
 * auditor works on.
 *
 * Everything here is shape and vocabulary: is this an object, does it declare a
 * version this build understands, is every key one of the documented ones, is
 * every route id an identifier rather than a pattern, is every field name a
 * token. Nothing here knows whether a route satisfies the policy, because that
 * is a question about the two documents together and it is answered in
 * `evaluate.mjs`.
 *
 * The supported input dialect is deliberately small and it is declared rather
 * than approximated. A construct this build does not implement -- a wildcard
 * route in an exception, a per-field option that belongs to a different field
 * -- is reported as unsupported or invalid and makes the run incomplete. It is
 * never quietly treated as satisfied, which is the failure mode that makes a
 * bounded validator dangerous instead of honest.
 */

import {
  MAX_DESCRIPTION_LENGTH,
  MAX_REASON_LENGTH,
  asciiLower,
  byCodeUnit,
  describeValue,
  excerpt,
  hasForbiddenCharacter,
  isCalendarDate,
  isHeaderName,
  isIdentifier,
  isPlainObject,
  looksLikePattern,
} from './text.mjs'

/** The only document version this build reads. Anything else is unsupported, not ignored. */
export const DOCUMENT_SCHEMA_VERSION = '1'

export const CAPTURE_DOCUMENT_KEYS = Object.freeze(['label', 'routes', 'schemaVersion'])
export const POLICY_DOCUMENT_KEYS = Object.freeze(['exceptions', 'forbidden', 'label', 'required', 'schemaVersion'])

export const ROUTE_KEYS = Object.freeze(['description', 'headers', 'id'])
export const HEADER_KEYS = Object.freeze(['name', 'value'])
export const REQUIREMENT_KEYS = Object.freeze([
  'allowedValues',
  'description',
  'forbiddenSources',
  'header',
  'minMaxAge',
  'requireIncludeSubDomains',
  'requirePreload',
  'requiredDirectives',
])
export const FORBIDDEN_KEYS = Object.freeze(['description', 'header'])
export const EXCEPTION_KEYS = Object.freeze(['expires', 'header', 'reason', 'route'])

/** The field names whose value this build parses structurally. */
export const CSP_HEADER = 'content-security-policy'
export const CSP_REPORT_ONLY_HEADER = 'content-security-policy-report-only'
export const HSTS_HEADER = 'strict-transport-security'

/** Requirement options that only mean something on one particular field. */
const CSP_ONLY_KEYS = Object.freeze(['forbiddenSources', 'requiredDirectives'])
const HSTS_ONLY_KEYS = Object.freeze(['minMaxAge', 'requireIncludeSubDomains', 'requirePreload'])

const MAX_ALLOWED_VALUES = 32
const MAX_ALLOWED_VALUE_LENGTH = 200
const MAX_REQUIRED_DIRECTIVES = 40
const MAX_FORBIDDEN_SOURCES = 40
const HARD_MAX_AGE = 315360000

function unknownKeys(value, allowed) {
  return Object.keys(value).filter((key) => !allowed.includes(key)).sort(byCodeUnit)
}

function strayKeyMessage(what, stray, allowed) {
  return `${what} declares unknown key(s) ${stray.map((key) => `"${excerpt(key, 60)}"`).join(', ')}; known keys are ${allowed.join(', ')}. An unknown key is refused rather than ignored, so a typo cannot disable a check.`
}

/**
 * Check the envelope both documents share: object, no stray keys, a version
 * this build implements, and a list of the expected kind wherever one appears.
 *
 * Returns `null` when the document is unusable as a whole.
 */
function openDocument(sink, file, value, documentKeys, listKeys) {
  if (!isPlainObject(value)) {
    sink.add({
      file,
      pointer: '',
      ruleId: 'document-invalid',
      message: `${file} must hold a JSON object; it holds ${describeValue(value)}.`,
    })
    return null
  }

  const stray = unknownKeys(value, documentKeys)
  if (stray.length > 0) {
    sink.add({ file, pointer: '', ruleId: 'document-invalid', message: strayKeyMessage(file, stray, documentKeys) })
    return null
  }

  if (value.schemaVersion !== DOCUMENT_SCHEMA_VERSION) {
    sink.add({
      file,
      pointer: '/schemaVersion',
      ruleId: 'schema-version-unsupported',
      message: `${file} declares schemaVersion ${describeValue(value.schemaVersion)}; this build implements version "${DOCUMENT_SCHEMA_VERSION}" only, and it does not guess at another one.`,
      suggestion: `Re-export the document as schemaVersion "${DOCUMENT_SCHEMA_VERSION}".`,
    })
    return null
  }

  if (value.label !== undefined && (typeof value.label !== 'string' || value.label.length > MAX_DESCRIPTION_LENGTH)) {
    sink.add({
      file,
      pointer: '/label',
      ruleId: 'document-invalid',
      message: `"label" must be a string of at most ${MAX_DESCRIPTION_LENGTH} characters; it is ${describeValue(value.label)}.`,
    })
    return null
  }

  for (const key of listKeys) {
    if (value[key] !== undefined && !Array.isArray(value[key])) {
      sink.add({
        file,
        pointer: `/${key}`,
        ruleId: 'document-invalid',
        message: `"${key}" must be an array; it is ${describeValue(value[key])}.`,
      })
      return null
    }
  }

  return { label: value.label === undefined ? '' : value.label }
}

function checkDescription(sink, file, pointer, description) {
  if (description === undefined) return true
  if (typeof description !== 'string' || description.length > MAX_DESCRIPTION_LENGTH) {
    sink.add({
      file,
      pointer: `${pointer}/description`,
      ruleId: 'document-invalid',
      message: `"description" must be a string of at most ${MAX_DESCRIPTION_LENGTH} characters; it is ${describeValue(description)}.`,
    })
    return false
  }
  return true
}

/**
 * Compile one captured route and its fields.
 *
 * A field entry that cannot be read is counted, not dropped silently: the route
 * then carries `refusedHeaders > 0` and the run is incomplete, because "this
 * route has no X-Frame-Options" and "this route has one field this tool could
 * not read" are different statements and only one of them is a finding about
 * the subject.
 */
function compileRoute(sink, file, raw, index, limits) {
  const pointer = `/routes/${index}`

  if (!isPlainObject(raw)) {
    sink.add({ file, pointer, ruleId: 'route-invalid', message: `A route entry must be an object; this is ${describeValue(raw)}.` })
    return null
  }

  const stray = unknownKeys(raw, ROUTE_KEYS)
  if (stray.length > 0) {
    sink.add({ file, pointer, ruleId: 'route-invalid', message: strayKeyMessage('This route', stray, ROUTE_KEYS) })
    return null
  }

  if (looksLikePattern(raw.id)) {
    sink.add({
      file,
      pointer: `${pointer}/id`,
      ruleId: 'pattern-unsupported',
      message: 'This route id is written as a pattern; a capture names one captured response per entry and this build never expands a pattern, so the entry was refused rather than matched against anything.',
      suggestion: 'Give each captured response its own route entry with a literal id.',
    })
    return null
  }

  if (!isIdentifier(raw.id)) {
    sink.add({
      file,
      pointer: `${pointer}/id`,
      ruleId: 'identifier-invalid',
      message: `This route has no usable id; it is ${describeValue(raw.id)}.`,
      suggestion: 'A route id is 1-120 characters from [A-Za-z0-9._:+/-], starting with a letter or digit.',
    })
    return null
  }

  if (!checkDescription(sink, file, pointer, raw.description)) return null

  if (!Array.isArray(raw.headers)) {
    sink.add({
      file,
      pointer: `${pointer}/headers`,
      ruleId: 'route-invalid',
      message: `"headers" must be an array of name and value objects; it is ${describeValue(raw.headers)}. Use [] for a response that genuinely carried no field worth capturing.`,
    })
    return null
  }

  if (raw.headers.length > limits.maxHeadersPerRoute) {
    sink.add({
      file,
      pointer: `${pointer}/headers`,
      ruleId: 'too-many-headers',
      message: `This route carries ${raw.headers.length} field(s), above the maxHeadersPerRoute limit of ${limits.maxHeadersPerRoute}; the route was refused rather than read in part.`,
      suggestion: 'Raise --max-headers-per-route, or trim the capture.',
    })
    return null
  }

  const headers = []
  const byName = new Map()
  let refusedHeaders = 0

  for (let position = 0; position < raw.headers.length; position += 1) {
    const entry = raw.headers[position]
    const headerPointer = `${pointer}/headers/${position}`

    if (!isPlainObject(entry)) {
      refusedHeaders += 1
      sink.add({ file, pointer: headerPointer, ruleId: 'header-invalid', message: `A field entry must be an object with a name and a value; this is ${describeValue(entry)}.` })
      continue
    }
    const headerStray = unknownKeys(entry, HEADER_KEYS)
    if (headerStray.length > 0) {
      refusedHeaders += 1
      sink.add({ file, pointer: headerPointer, ruleId: 'header-invalid', message: strayKeyMessage('This field entry', headerStray, HEADER_KEYS) })
      continue
    }
    if (!isHeaderName(entry.name)) {
      refusedHeaders += 1
      sink.add({
        file,
        pointer: `${headerPointer}/name`,
        ruleId: 'header-invalid',
        message: `This field has no usable name; it is ${describeValue(entry.name)}.`,
        suggestion: 'A field name is an RFC 9110 token of 1-80 characters.',
      })
      continue
    }
    if (typeof entry.value !== 'string') {
      refusedHeaders += 1
      sink.add({
        file,
        pointer: `${headerPointer}/value`,
        ruleId: 'header-invalid',
        message: `The value of "${excerpt(entry.name, 80)}" must be a string; it is ${describeValue(entry.value)}.`,
      })
      continue
    }

    const name = asciiLower(entry.name)
    const compiled = { name, rawName: entry.name, value: entry.value, pointer: headerPointer, problem: null }

    // The two evidence problems below leave the field present but unreadable.
    // The name is known, so the field is not missing; the value is refused, so
    // no verdict about the value is available. Both facts are recorded, and
    // neither is allowed to become a pass.
    if (entry.value.length > limits.maxHeaderValueLength) {
      compiled.problem = 'too-long'
      sink.add({
        file,
        pointer: `${headerPointer}/value`,
        ruleId: 'header-value-too-long',
        message: `The value of "${name}" is ${entry.value.length} characters, above the maxHeaderValueLength limit of ${limits.maxHeaderValueLength}; it was not parsed, so nothing about it was decided.`,
        suggestion: 'Raise --max-header-value-length if the capture is genuine.',
      })
    } else if (hasForbiddenCharacter(entry.value)) {
      compiled.problem = 'forbidden-character'
      sink.add({
        file,
        pointer: `${headerPointer}/value`,
        ruleId: 'header-value-control-character',
        message: `The value of "${name}" carries a control, separator or bidi character, which no field value may contain; it was refused unparsed and is not reproduced here.`,
        suggestion: 'Re-export the capture, and check whatever produced this response for field injection.',
      })
    }

    headers.push(compiled)
    const existing = byName.get(name)
    if (existing === undefined) byName.set(name, [compiled])
    else existing.push(compiled)
  }

  return {
    id: raw.id,
    index,
    pointer,
    description: raw.description === undefined ? '' : raw.description,
    declaredHeaders: raw.headers.length,
    headers,
    byName,
    refusedHeaders,
  }
}

/**
 * Compile a capture document.
 *
 * Returns `null` when the document as a whole is unusable. A document that
 * compiles may still have refused routes; `declaredRoutes` and `routes.length`
 * differ in that case, and the caller treats the gap as missing evidence rather
 * than as a clean result.
 */
export function compileCapture(sink, file, value, limits) {
  const opened = openDocument(sink, file, value, CAPTURE_DOCUMENT_KEYS, ['routes'])
  if (opened === null) return null

  if (value.routes === undefined) {
    sink.add({
      file,
      pointer: '',
      ruleId: 'document-invalid',
      message: `${file} declares no "routes" array, so there is nothing to audit; declare it, using [] for a capture that deliberately holds no response.`,
    })
    return null
  }

  if (value.routes.length > limits.maxRoutes) {
    sink.add({
      file,
      pointer: '/routes',
      ruleId: 'too-many-routes',
      message: `${file} declares ${value.routes.length} route(s), above the maxRoutes limit of ${limits.maxRoutes}; nothing was compiled from it rather than a prefix being read and reported as the whole.`,
      suggestion: 'Raise --max-routes, or split the capture.',
    })
    return null
  }

  const routes = []
  const byId = new Map()

  for (let index = 0; index < value.routes.length; index += 1) {
    const route = compileRoute(sink, file, value.routes[index], index, limits)
    if (route === null) continue
    if (byId.has(route.id)) {
      sink.add({
        file,
        pointer: `${route.pointer}/id`,
        ruleId: 'route-duplicate',
        message: `Route id "${excerpt(route.id, 120)}" is declared twice, at ${byId.get(route.id).pointer} and here; neither copy is authoritative, so this one was refused.`,
      })
      continue
    }
    byId.set(route.id, route)
    routes.push(route)
  }

  return { label: opened.label, declaredRoutes: value.routes.length, routes, byId }
}

function compileRequirement(sink, file, raw, index) {
  const pointer = `/required/${index}`

  if (!isPlainObject(raw)) {
    sink.add({ file, pointer, ruleId: 'policy-invalid', message: `A requirement must be an object; this is ${describeValue(raw)}.` })
    return null
  }
  const stray = unknownKeys(raw, REQUIREMENT_KEYS)
  if (stray.length > 0) {
    sink.add({ file, pointer, ruleId: 'policy-invalid', message: strayKeyMessage('This requirement', stray, REQUIREMENT_KEYS) })
    return null
  }
  if (!isHeaderName(raw.header)) {
    sink.add({
      file,
      pointer: `${pointer}/header`,
      ruleId: 'policy-invalid',
      message: `This requirement names no usable field; "header" is ${describeValue(raw.header)}.`,
      suggestion: 'A field name is an RFC 9110 token of 1-80 characters, for example content-security-policy.',
    })
    return null
  }
  if (!checkDescription(sink, file, pointer, raw.description)) return null

  const header = asciiLower(raw.header)
  const requirement = {
    header,
    index,
    pointer,
    description: raw.description === undefined ? '' : raw.description,
    allowedValues: null,
    requiredDirectives: null,
    forbiddenSources: null,
    minMaxAge: null,
    requireIncludeSubDomains: null,
    requirePreload: null,
  }

  // An option that belongs to a different field is refused rather than ignored.
  // Silently dropping minMaxAge from an X-Frame-Options requirement would leave
  // a policy author believing a bound is enforced that nothing enforces.
  const misplacedCsp = header === CSP_HEADER ? [] : CSP_ONLY_KEYS.filter((key) => raw[key] !== undefined)
  const misplacedHsts = header === HSTS_HEADER ? [] : HSTS_ONLY_KEYS.filter((key) => raw[key] !== undefined)
  const misplaced = [...misplacedCsp, ...misplacedHsts].sort(byCodeUnit)
  if (misplaced.length > 0) {
    const onlyOn = [
      ...(misplacedCsp.length > 0 ? [CSP_HEADER] : []),
      ...(misplacedHsts.length > 0 ? [HSTS_HEADER] : []),
    ].join(' and ')
    sink.add({
      file,
      pointer,
      ruleId: 'policy-invalid',
      message: `The requirement for "${header}" declares ${misplaced.map((key) => `"${key}"`).join(', ')}, which this build reads only on ${onlyOn}; it was refused rather than ignored.`,
      suggestion: 'Remove the option, or move it to the requirement for the field it describes.',
    })
    return null
  }

  if (raw.allowedValues !== undefined) {
    if (!Array.isArray(raw.allowedValues) || raw.allowedValues.length === 0 || raw.allowedValues.length > MAX_ALLOWED_VALUES) {
      sink.add({
        file,
        pointer: `${pointer}/allowedValues`,
        ruleId: 'policy-invalid',
        message: `"allowedValues" must be an array of 1-${MAX_ALLOWED_VALUES} strings; it is ${describeValue(raw.allowedValues)}.`,
      })
      return null
    }
    const values = []
    for (let position = 0; position < raw.allowedValues.length; position += 1) {
      const candidate = raw.allowedValues[position]
      if (typeof candidate !== 'string' || candidate.length === 0 || candidate.length > MAX_ALLOWED_VALUE_LENGTH || hasForbiddenCharacter(candidate)) {
        sink.add({
          file,
          pointer: `${pointer}/allowedValues/${position}`,
          ruleId: 'policy-invalid',
          message: `An allowed value must be a control-free string of 1-${MAX_ALLOWED_VALUE_LENGTH} characters; this is ${describeValue(candidate)}.`,
        })
        return null
      }
      values.push(asciiLower(candidate.trim()))
    }
    requirement.allowedValues = [...new Set(values)].sort(byCodeUnit)
  }

  if (raw.requiredDirectives !== undefined) {
    if (!Array.isArray(raw.requiredDirectives) || raw.requiredDirectives.length === 0 || raw.requiredDirectives.length > MAX_REQUIRED_DIRECTIVES) {
      sink.add({
        file,
        pointer: `${pointer}/requiredDirectives`,
        ruleId: 'policy-invalid',
        message: `"requiredDirectives" must be an array of 1-${MAX_REQUIRED_DIRECTIVES} directive names; it is ${describeValue(raw.requiredDirectives)}.`,
      })
      return null
    }
    const names = []
    for (let position = 0; position < raw.requiredDirectives.length; position += 1) {
      const candidate = raw.requiredDirectives[position]
      if (typeof candidate !== 'string' || !/^[A-Za-z0-9-]{1,60}$/.test(candidate)) {
        sink.add({
          file,
          pointer: `${pointer}/requiredDirectives/${position}`,
          ruleId: 'policy-invalid',
          message: `A directive name is 1-60 characters from [A-Za-z0-9-]; this is ${describeValue(candidate)}.`,
        })
        return null
      }
      names.push(asciiLower(candidate))
    }
    // Not sorted: this list is only ever tested for membership and never
    // reaches output, so an order here would be an ordering site no test could
    // pin. Deduplication keeps it deterministic; insertion order keeps it
    // readable against the policy it came from.
    requirement.requiredDirectives = [...new Set(names)]
  }

  if (raw.forbiddenSources !== undefined) {
    if (!Array.isArray(raw.forbiddenSources) || raw.forbiddenSources.length === 0 || raw.forbiddenSources.length > MAX_FORBIDDEN_SOURCES) {
      sink.add({
        file,
        pointer: `${pointer}/forbiddenSources`,
        ruleId: 'policy-invalid',
        message: `"forbiddenSources" must be an array of 1-${MAX_FORBIDDEN_SOURCES} source expressions; it is ${describeValue(raw.forbiddenSources)}.`,
      })
      return null
    }
    const sources = []
    for (let position = 0; position < raw.forbiddenSources.length; position += 1) {
      const candidate = raw.forbiddenSources[position]
      const unusable = typeof candidate !== 'string'
        || candidate.length === 0
        || candidate.length > MAX_ALLOWED_VALUE_LENGTH
        || hasForbiddenCharacter(candidate)
        || /[ \t;]/.test(candidate)
      if (unusable) {
        sink.add({
          file,
          pointer: `${pointer}/forbiddenSources/${position}`,
          ruleId: 'policy-invalid',
          message: `A forbidden source is one control-free source expression with no space or semicolon in it; this is ${describeValue(candidate)}.`,
        })
        return null
      }
      sources.push(asciiLower(candidate))
    }
    // Not sorted, for the same reason as requiredDirectives above.
    requirement.forbiddenSources = [...new Set(sources)]
  }

  if (raw.minMaxAge !== undefined) {
    if (!Number.isInteger(raw.minMaxAge) || raw.minMaxAge < 0 || raw.minMaxAge > HARD_MAX_AGE) {
      sink.add({
        file,
        pointer: `${pointer}/minMaxAge`,
        ruleId: 'policy-invalid',
        message: `"minMaxAge" must be an integer between 0 and ${HARD_MAX_AGE} seconds; it is ${describeValue(raw.minMaxAge)}.`,
      })
      return null
    }
    requirement.minMaxAge = raw.minMaxAge
  }

  for (const key of ['requireIncludeSubDomains', 'requirePreload']) {
    if (raw[key] === undefined) continue
    if (typeof raw[key] !== 'boolean') {
      sink.add({
        file,
        pointer: `${pointer}/${key}`,
        ruleId: 'policy-invalid',
        message: `"${key}" must be true or false; it is ${describeValue(raw[key])}.`,
      })
      return null
    }
    requirement[key] = raw[key]
  }

  return requirement
}

function compileForbidden(sink, file, raw, index) {
  const pointer = `/forbidden/${index}`

  if (!isPlainObject(raw)) {
    sink.add({ file, pointer, ruleId: 'policy-invalid', message: `A forbidden entry must be an object; this is ${describeValue(raw)}.` })
    return null
  }
  const stray = unknownKeys(raw, FORBIDDEN_KEYS)
  if (stray.length > 0) {
    sink.add({ file, pointer, ruleId: 'policy-invalid', message: strayKeyMessage('This forbidden entry', stray, FORBIDDEN_KEYS) })
    return null
  }
  if (!isHeaderName(raw.header)) {
    sink.add({
      file,
      pointer: `${pointer}/header`,
      ruleId: 'policy-invalid',
      message: `This forbidden entry names no usable field; "header" is ${describeValue(raw.header)}.`,
    })
    return null
  }
  if (!checkDescription(sink, file, pointer, raw.description)) return null

  return { header: asciiLower(raw.header), index, pointer, description: raw.description === undefined ? '' : raw.description }
}

/**
 * Compile one route exception.
 *
 * A waiver is the one construct in this tool that turns a failure into a pass,
 * so it is the construct held to the strictest shape: an exact route, an exact
 * field, a reason somebody wrote, and a date it stops applying. A waiver with
 * no expiry is a policy change wearing a waiver's clothes, and a waiver with no
 * reason is unreviewable, so neither is accepted.
 */
function compileException(sink, file, raw, index) {
  const pointer = `/exceptions/${index}`

  if (!isPlainObject(raw)) {
    sink.add({ file, pointer, ruleId: 'policy-invalid', message: `An exception must be an object; this is ${describeValue(raw)}.` })
    return null
  }
  const stray = unknownKeys(raw, EXCEPTION_KEYS)
  if (stray.length > 0) {
    sink.add({ file, pointer, ruleId: 'policy-invalid', message: strayKeyMessage('This exception', stray, EXCEPTION_KEYS) })
    return null
  }
  if (looksLikePattern(raw.route) || looksLikePattern(raw.header)) {
    sink.add({
      file,
      pointer,
      ruleId: 'pattern-unsupported',
      message: 'This exception names a route or a field as a pattern; a waiver applies to one route and one field, and this build never expands a pattern into the set of things it might excuse, so the exception was refused.',
      suggestion: 'Write one exception per route and field, with literal names.',
    })
    return null
  }
  if (!isIdentifier(raw.route)) {
    sink.add({
      file,
      pointer: `${pointer}/route`,
      ruleId: 'policy-invalid',
      message: `This exception names no usable route; "route" is ${describeValue(raw.route)}.`,
    })
    return null
  }
  if (!isHeaderName(raw.header)) {
    sink.add({
      file,
      pointer: `${pointer}/header`,
      ruleId: 'policy-invalid',
      message: `This exception names no usable field; "header" is ${describeValue(raw.header)}.`,
    })
    return null
  }
  if (typeof raw.reason !== 'string' || raw.reason.trim().length === 0 || raw.reason.length > MAX_REASON_LENGTH) {
    sink.add({
      file,
      pointer: `${pointer}/reason`,
      ruleId: 'exception-reason-missing',
      message: `This exception carries no usable reason; "reason" is ${describeValue(raw.reason)}. A waiver nobody can review is a waiver nobody agreed to, so it was refused and nothing is excused by it.`,
      suggestion: 'Write why the deviation is accepted and who accepted it.',
    })
    return null
  }
  if (!isCalendarDate(raw.expires)) {
    sink.add({
      file,
      pointer: `${pointer}/expires`,
      ruleId: 'exception-expiry-missing',
      message: `This exception carries no usable expiry; "expires" is ${describeValue(raw.expires)}. A waiver with no end date is a policy change, so it was refused and nothing is excused by it.`,
      suggestion: 'Set "expires" to a calendar date written YYYY-MM-DD.',
    })
    return null
  }

  return { route: raw.route, header: asciiLower(raw.header), reason: raw.reason.trim(), expires: raw.expires, index, pointer }
}

/**
 * Compile a policy document.
 *
 * The policy is an input, not configuration: it arrives in a file the run was
 * pointed at, so a problem with it is reported as a finding about that file and
 * makes the run incomplete. Configuration is what the command line carries, and
 * a problem with that leaves stdout empty instead.
 */
export function compilePolicy(sink, file, value, limits) {
  const opened = openDocument(sink, file, value, POLICY_DOCUMENT_KEYS, ['exceptions', 'forbidden', 'required'])
  if (opened === null) return null

  const rawRequired = value.required ?? []
  const rawForbidden = value.forbidden ?? []
  const rawExceptions = value.exceptions ?? []

  if (rawRequired.length + rawForbidden.length > limits.maxRequirements) {
    sink.add({
      file,
      pointer: '/required',
      ruleId: 'too-many-requirements',
      message: `${file} declares ${rawRequired.length + rawForbidden.length} required and forbidden field(s) together, above the maxRequirements limit of ${limits.maxRequirements}; nothing was compiled from it.`,
      suggestion: 'Raise --max-requirements, or split the policy.',
    })
    return null
  }
  if (rawExceptions.length > limits.maxExceptions) {
    sink.add({
      file,
      pointer: '/exceptions',
      ruleId: 'too-many-exceptions',
      message: `${file} declares ${rawExceptions.length} exception(s), above the maxExceptions limit of ${limits.maxExceptions}; nothing was compiled from it.`,
      suggestion: 'Raise --max-exceptions, or retire some waivers.',
    })
    return null
  }

  const required = []
  const requiredByHeader = new Map()
  for (let index = 0; index < rawRequired.length; index += 1) {
    const requirement = compileRequirement(sink, file, rawRequired[index], index)
    if (requirement === null) continue
    if (requiredByHeader.has(requirement.header)) {
      sink.add({
        file,
        pointer: `${requirement.pointer}/header`,
        ruleId: 'policy-invalid',
        message: `"${requirement.header}" is required twice, at ${requiredByHeader.get(requirement.header).pointer} and here; neither copy is authoritative, so this one was refused.`,
      })
      continue
    }
    requiredByHeader.set(requirement.header, requirement)
    required.push(requirement)
  }

  const forbidden = []
  const forbiddenByHeader = new Map()
  const contradicted = new Set()
  for (let index = 0; index < rawForbidden.length; index += 1) {
    const entry = compileForbidden(sink, file, rawForbidden[index], index)
    if (entry === null) continue
    if (forbiddenByHeader.has(entry.header)) {
      sink.add({
        file,
        pointer: `${entry.pointer}/header`,
        ruleId: 'policy-invalid',
        message: `"${entry.header}" is forbidden twice, at ${forbiddenByHeader.get(entry.header).pointer} and here; neither copy is authoritative, so this one was refused.`,
      })
      continue
    }
    forbiddenByHeader.set(entry.header, entry)
    // A field the policy both demands and bans cannot be satisfied by any
    // response at all. That is a contradiction inside the policy, and it is
    // reported as one rather than resolved in whichever order the lists happen
    // to be read.
    if (requiredByHeader.has(entry.header)) {
      contradicted.add(entry.header)
      sink.add({
        file,
        pointer: entry.pointer,
        ruleId: 'policy-contradiction',
        message: `"${entry.header}" is both required at ${requiredByHeader.get(entry.header).pointer} and forbidden here; no response can satisfy both, so neither entry was evaluated against any route.`,
        suggestion: 'Decide whether the field is required or forbidden and remove the other entry.',
      })
      continue
    }
    forbidden.push(entry)
  }

  const exceptions = []
  const seenException = new Set()
  for (let index = 0; index < rawExceptions.length; index += 1) {
    const exception = compileException(sink, file, rawExceptions[index], index)
    if (exception === null) continue
    const key = `${exception.route} ${exception.header}`
    if (seenException.has(key)) {
      sink.add({
        file,
        pointer: exception.pointer,
        ruleId: 'policy-invalid',
        message: `A waiver for route "${excerpt(exception.route, 100)}" and field "${exception.header}" is declared more than once; neither copy is authoritative, so this one was refused.`,
      })
      continue
    }
    seenException.add(key)
    exceptions.push(exception)
  }

  return {
    label: opened.label,
    declaredRequired: rawRequired.length,
    declaredForbidden: rawForbidden.length,
    declaredExceptions: rawExceptions.length,
    required: required.filter((requirement) => !contradicted.has(requirement.header)),
    forbidden,
    exceptions,
    contradicted,
  }
}
