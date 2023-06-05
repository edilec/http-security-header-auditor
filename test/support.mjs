/**
 * Fixtures and runners shared by the test suite.
 *
 * Two entry points are exercised throughout: `apiReport` calls the exported
 * function, and `cliRun` spawns the real binary and reads the real exit code.
 * Several guarantees in this package can only be pinned by the second -- an exit
 * code cannot be satisfied by editing a table.
 *
 * Everything here builds *inputs*. Nothing here decides what a test expects: no
 * severity, no rule id, no count and no ordering lives in this file, so a test
 * cannot accidentally assert a value against the same declaration that produced
 * it.
 */

import { execFile } from 'node:child_process'
import { mkdtemp, rm, writeFile } from 'node:fs/promises'
import { tmpdir } from 'node:os'
import { dirname, join, resolve } from 'node:path'
import { fileURLToPath } from 'node:url'
import { promisify } from 'node:util'

import { auditHeaders } from '../src/index.mjs'

const execFileAsync = promisify(execFile)

export const projectDirectory = resolve(dirname(fileURLToPath(import.meta.url)), '..')
export const CLI = join(projectDirectory, 'bin/http-security-header-auditor.mjs')

/** A date every test that needs one uses, so no test depends on when it runs. */
export const AS_OF = '2026-03-01'

export const header = (name, value) => ({ name, value })

export function route(id, headers, description) {
  const entry = { id }
  if (description !== undefined) entry.description = description
  entry.headers = headers
  return entry
}

export function requirement(headerName, extra = {}) {
  return { header: headerName, ...extra }
}

export const forbid = (headerName, description) =>
  (description === undefined ? { header: headerName } : { header: headerName, description })

export const exception = (routeId, headerName, reason, expires) => ({ route: routeId, header: headerName, reason, expires })

export const captureDocument = (routes, label) =>
  (label === undefined ? { schemaVersion: '1', routes } : { schemaVersion: '1', label, routes })

export const policyDocument = (parts = {}) => ({ schemaVersion: '1', ...parts })

/** The two documents, as objects, under their default names. */
export const fixture = (policy, routes) => ({
  'policy.json': policyDocument(policy),
  'capture.json': captureDocument(routes),
})

/**
 * A capture that raises nothing at all against its policy: one required field,
 * present, with an allowed value. Tests break exactly one thing in it so that
 * the finding they assert is the only finding there is.
 */
export const clean = () => fixture(
  { required: [requirement('x-content-type-options', { allowedValues: ['nosniff'] })] },
  [route('ok', [header('X-Content-Type-Options', 'nosniff')])],
)

/**
 * Create a temporary root, write the named files into it, run `body(root)`, and
 * remove the tree afterwards whatever happened.
 *
 * A string is written verbatim and a `Uint8Array` byte for byte, so a test can
 * plant text that is not JSON, or bytes that are not UTF-8 at all.
 */
export async function withRoot(files, body) {
  const root = await mkdtemp(join(tmpdir(), 'http-security-header-auditor-'))
  try {
    for (const [name, content] of Object.entries(files)) {
      const bytes = typeof content === 'string' || content instanceof Uint8Array
        ? content
        : `${JSON.stringify(content, null, 2)}\n`
      await writeFile(join(root, name), bytes)
    }
    return await body(root)
  } finally {
    await rm(root, { recursive: true, force: true })
  }
}

/** Run the exported API over a temporary root. */
export async function apiReport(files, options = {}) {
  return withRoot(files, (root) => auditHeaders({ root, ...options }))
}

/** Spawn the real binary. Returns the exit code and both streams; never throws on a non-zero exit. */
export async function cliRun(args) {
  try {
    const { stdout, stderr } = await execFileAsync(process.execPath, [CLI, ...args], {
      cwd: projectDirectory,
      maxBuffer: 64 * 1024 * 1024,
    })
    return { code: 0, stdout, stderr }
  } catch (error) {
    return { code: error.code, stdout: error.stdout ?? '', stderr: error.stderr ?? '' }
  }
}

/** Spawn the real binary over a temporary root, and parse whatever stdout carried. */
export async function cliReport(files, extraArgs = []) {
  return withRoot(files, async (root) => {
    const result = await cliRun(['--root', root, '--json', ...extraArgs])
    return { ...result, report: result.stdout === '' ? null : JSON.parse(result.stdout) }
  })
}

/**
 * Spawn the real binary with the human summary left on, so stderr carries it.
 *
 * `cliReport` passes `--json`, which suppresses that summary; a test that means
 * to inspect the printed lines has to ask for them.
 */
export async function cliHuman(files, extraArgs = []) {
  return withRoot(files, async (root) => {
    const result = await cliRun(['--root', root, ...extraArgs])
    return { ...result, report: result.stdout === '' ? null : JSON.parse(result.stdout) }
  })
}

/** Every rule id a report raised, deduplicated and ordered. */
export const raisedRules = (report) =>
  [...new Set(report.findings.map((finding) => finding.ruleId))].sort()

/** The findings for one rule id, in emitted order. */
export const findingsFor = (report, ruleId) => report.findings.filter((finding) => finding.ruleId === ruleId)

/** The row for one route id. */
export const routeRow = (report, id) => report.routes.find((row) => row.id === id)

/**
 * One character from each class the report contract names, built from code
 * points so every test file that uses them stays plain ASCII and readable.
 */
export const FORBIDDEN = Object.freeze({
  'C0 NUL': String.fromCharCode(0x00),
  'C0 LF': String.fromCharCode(0x0a),
  'C0 ESC': String.fromCharCode(0x1b),
  DEL: String.fromCharCode(0x7f),
  'C1 NEL': String.fromCharCode(0x85),
  'C1 CSI': String.fromCharCode(0x9b),
  'line separator': String.fromCharCode(0x2028),
  'paragraph separator': String.fromCharCode(0x2029),
  'bidi LRM': String.fromCharCode(0x200e),
  'bidi RLM': String.fromCharCode(0x200f),
  'bidi RLO': String.fromCharCode(0x202e),
  'bidi isolate': String.fromCharCode(0x2066),
})

/**
 * A published placeholder, never a real credential.
 *
 * AWS documents this exact key id as an example, and it is used here only to
 * prove that a value which *looks* like a secret is never echoed out of a field
 * the tool refused. Nothing in this package treats it specially.
 */
export const CANARY = 'AKIAIOSFODNN7EXAMPLE'
