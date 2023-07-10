/**
 * "Nothing is fetched, no host is resolved, no endpoint is discovered", proved
 * rather than asserted.
 *
 * This is the acceptance property that is easiest to claim and hardest to check,
 * so it is checked four ways, because each of them can be true while the
 * property is false:
 *
 * 1. A module resolution hook and runtime API guards refuse network access
 *    before the binary loads. Safe import, data-URL fetch and null-receiver
 *    connect controls prove each guard fires without opening a socket.
 * 2. Inert URL-shaped CSP, report and route data run through the real binary
 *    under the guard. Input content is never an instruction to fetch it.
 * 3. A scan of the shipped source for the globals and spellings a hook cannot
 *    see: `fetch`, `eval`, a child process that would open a socket on this
 *    package's behalf, and anything that would read a credential.
 * 4. A check of the input schema itself. A capture has nowhere to put an
 *    address, which is the structural half of the promise: there is nothing here
 *    for a fetch to take even if one were added.
 */

import assert from 'node:assert/strict'
import { execFile } from 'node:child_process'
import { mkdtemp, readFile, readdir, rm, writeFile } from 'node:fs/promises'
import { tmpdir } from 'node:os'
import { join } from 'node:path'
import { pathToFileURL } from 'node:url'
import test from 'node:test'
import { promisify } from 'node:util'

import { ROUTE_KEYS, HEADER_KEYS } from '../src/index.mjs'
import { CLI, apiReport, header, projectDirectory, route, withRoot } from './support.mjs'

const execFileAsync = promisify(execFile)

const NETWORK_MODULES = [
  'net', 'http', 'https', 'http2', 'dgram', 'dns', 'tls', 'cluster', 'quic', 'inspector',
]

const HOOK_SOURCE = `
const blocked = new Set(${JSON.stringify(NETWORK_MODULES)})
export async function resolve(specifier, context, next) {
  const bare = specifier.startsWith('node:') ? specifier.slice(5) : specifier
  if (blocked.has(bare.split('/')[0])) throw new Error('BLOCKED_NETWORK_IMPORT:' + specifier)
  return next(specifier, context)
}
`

const GUARD_SOURCE = `
import { register, syncBuiltinESMExports } from 'node:module'
import net from 'node:net'
import http from 'node:http'
import https from 'node:https'
import http2 from 'node:http2'
import tls from 'node:tls'
import dgram from 'node:dgram'
import dns from 'node:dns'
const forbidden = () => { throw new Error('BLOCKED_NETWORK_OPERATION') }
net.Socket.prototype.connect = forbidden
net.Server.prototype.listen = forbidden
net.connect = forbidden
net.createConnection = forbidden
http.request = forbidden
http.get = forbidden
https.request = forbidden
https.get = forbidden
http2.connect = forbidden
tls.connect = forbidden
dgram.Socket.prototype.bind = forbidden
dgram.Socket.prototype.send = forbidden
dns.lookup = forbidden
dns.resolve = forbidden
globalThis.fetch = forbidden
globalThis.WebSocket = forbidden
syncBuiltinESMExports()
register('./hook.mjs', import.meta.url)
`

const PROBE_SOURCE = `
import net from 'node:net'
process.stdout.write(typeof net)
`

const FETCH_PROBE_SOURCE = `await fetch('data:text/plain,offline')`
const CONNECT_PROBE_SOURCE = `process.getBuiltinModule('node:net').Socket.prototype.connect.call(null)`

const POLICY = {
  schemaVersion: '1',
  required: [{ header: 'content-security-policy', requiredDirectives: ['default-src'], forbiddenSources: ["'unsafe-inline'"] }],
}

async function withGuard(body) {
  const directory = await mkdtemp(join(tmpdir(), 'http-security-header-auditor-guard-'))
  try {
    await writeFile(join(directory, 'hook.mjs'), HOOK_SOURCE)
    await writeFile(join(directory, 'guard.mjs'), GUARD_SOURCE)
    await writeFile(join(directory, 'probe.mjs'), PROBE_SOURCE)
    await writeFile(join(directory, 'fetch-probe.mjs'), FETCH_PROBE_SOURCE)
    await writeFile(join(directory, 'connect-probe.mjs'), CONNECT_PROBE_SOURCE)
    return await body({ directory, guard: pathToFileURL(join(directory, 'guard.mjs')).href })
  } finally {
    await rm(directory, { recursive: true, force: true })
  }
}

test('the binary completes a real run with network imports and APIs disabled', async () => {
  await withGuard(async ({ directory, guard }) => {
    // The control first: a script that does reach for a socket must fail under
    // the same guard, or this case would pass on a hook that never fires.
    await assert.rejects(
      () => execFileAsync(process.execPath, ['--import', guard, join(directory, 'probe.mjs')]),
      /BLOCKED_NETWORK_IMPORT:node:net/,
    )
    await assert.rejects(
      () => execFileAsync(process.execPath, ['--import', guard, join(directory, 'fetch-probe.mjs')]),
      /BLOCKED_NETWORK_OPERATION/,
    )
    await assert.rejects(
      () => execFileAsync(process.execPath, ['--import', guard, join(directory, 'connect-probe.mjs')]),
      /BLOCKED_NETWORK_OPERATION/,
    )

    const { stdout } = await withRoot({
      'policy.json': POLICY,
      'capture.json': {
        schemaVersion: '1',
        routes: [route('app', [header('Content-Security-Policy', "default-src 'self'; report-uri https://reports.example.invalid/csp")])],
      },
    }, (root) => execFileAsync(process.execPath, ['--import', guard, CLI, '--root', root, '--json']))

    const report = JSON.parse(stdout)
    assert.equal(report.status, 'pass')
    assert.equal(report.summary.checked, 1)
  })
})

test('inert URL-shaped policy and capture evidence remain data under the network guard', async () => {
  await withGuard(async ({ guard }) => {
    const origin = 'http://127.0.0.1:8080'
    const documents = {
      'policy.json': {
        schemaVersion: '1',
        label: `baseline for ${origin}`,
        required: [{ header: 'content-security-policy', description: `as served by ${origin}` }],
      },
      'capture.json': {
        schemaVersion: '1',
        label: `captured from ${origin}`,
        routes: [route(
          'app',
          [header('Content-Security-Policy', `default-src 'self' ${origin}; report-uri ${origin}/csp-reports`)],
          `GET ${origin}/`,
        )],
      },
    }
    const { stdout } = await withRoot(documents, (root) =>
      execFileAsync(process.execPath, ['--import', guard, CLI, '--root', root, '--json']))
    const report = JSON.parse(stdout)
    assert.equal(report.status, 'pass')
    assert.equal(report.summary.checked, 1)
  })
})

async function shippedSource() {
  const parts = []
  for (const directory of ['bin', 'src']) {
    for (const name of (await readdir(join(projectDirectory, directory))).sort()) {
      parts.push(await readFile(join(projectDirectory, directory, name), 'utf8'))
    }
  }
  return parts.join(String.fromCharCode(10))
}

test('the shipped source reaches for nothing that could open a socket', async () => {
  const source = await shippedSource()

  for (const name of NETWORK_MODULES) {
    assert.equal(source.includes(`node:${name}`), false, `the source imports node:${name}`)
  }
  for (const name of ['XMLHttpRequest', 'WebSocket', 'EventSource', 'sendBeacon', 'node:child_process', 'node:worker_threads', 'node:vm']) {
    assert.equal(source.includes(name), false, `the source reaches for ${name}`)
  }
  assert.equal(/\bfetch\s*\(/.test(source), false, 'the source calls fetch')
  assert.equal(/\bnew\s+Request\b/.test(source), false)
  assert.equal(/\beval\s*\(/.test(source), false)
  assert.equal(/\bnew\s+Function\b/.test(source), false)
  assert.equal(/\bnew\s+URL\s*\(/.test(source), false, 'nothing here even parses a URL, let alone resolves one')
})

test('the shipped source never reads a credential, a clock or a random source', async () => {
  const source = await shippedSource()

  for (const name of ['process.stdin', 'node:readline', 'process.env', 'getPassword', 'prompt(']) {
    assert.equal(source.includes(name), false, `the source reaches for ${name}`)
  }
  assert.equal(/\bMath\.random\b/.test(source), false)
  assert.equal(/\bDate\.now\b/.test(source), false)
  assert.equal(/\bnew\s+Date\b/.test(source), false, 'the only date this tool knows is the one --as-of carries')
  assert.equal(/\.localeCompare\(/.test(source), false)
  assert.equal(/\bIntl\b/.test(source), false)

  // The file system is reached through exactly one import whose bindings are
  // all read-only. Listing the verbs that must be absent would pass on a prose
  // mention and fail on one; naming the bindings that are present is the
  // assertion that means something.
  const fsImports = source.match(/import \{[^}]*\} from 'node:fs[^']*'/g) ?? []
  assert.deepEqual(fsImports, ["import { readFile, realpath, stat } from 'node:fs/promises'"])
  assert.equal(/from 'node:fs'/.test(source), false, 'no synchronous file system surface either')
})

test('no regular expression in the shipped source is built from input', async () => {
  const source = await shippedSource()

  // Every `new RegExp` in this package is a module-level constant assembled from
  // literal code points, which is why the pattern below insists on the `const`
  // in front of it. A pattern compiled from a capture would be a bound nobody
  // could enforce: you cannot time-limit a regular expression, because the
  // engine does not yield.
  const constructions = source.match(/new RegExp\(/g) ?? []
  const constants = source.match(/^const [A-Z_]+ = new RegExp\($/gm) ?? []
  assert.equal(constructions.length, constants.length, 'a RegExp is built somewhere other than a module constant')
  assert.equal(constructions.length, 2, 'the two control-character classes, and nothing else')
})

test('the input schema has nowhere to put an address', async () => {
  // The structural half of the promise. A route is an opaque name; there is no
  // url, host, origin, endpoint or address key anywhere in a capture, so there
  // is nothing for a fetch to take even if one were added.
  assert.deepEqual(ROUTE_KEYS, ['description', 'headers', 'id'])
  assert.deepEqual(HEADER_KEYS, ['name', 'value'])

  const report = await apiReport({
    'policy.json': POLICY,
    'capture.json': {
      schemaVersion: '1',
      routes: [{ id: 'app', url: 'https://app.example.invalid/', headers: [] }],
    },
  })

  assert.equal(report.status, 'incomplete', 'a url key is an unknown key, and an unknown key is refused')
  assert.equal(report.findings.some((finding) => finding.ruleId === 'route-invalid'), true)
  assert.equal(report.findings.some((finding) => finding.message.includes('"url"')), true)
})

test('the manifest declares no dependency of any kind', async () => {
  const manifest = JSON.parse(await readFile(join(projectDirectory, 'package.json'), 'utf8'))

  assert.equal(Object.hasOwn(manifest, 'dependencies'), false)
  assert.equal(Object.hasOwn(manifest, 'devDependencies'), false)
  assert.equal(Object.hasOwn(manifest, 'peerDependencies'), false)
  assert.equal(Object.hasOwn(manifest, 'optionalDependencies'), false)
  assert.equal(manifest.version, '0.1.0')
  assert.equal(manifest.engines.node, '>=22')
})

test('the documentation says plainly what the tool does not do', async () => {
  const readme = await readFile(join(projectDirectory, 'README.md'), 'utf8')

  assert.equal(readme.includes('Limits and non-goals'), true)
  assert.equal(readme.includes('no endpoint discovery'), true)
  assert.equal(readme.includes('scan'), true)
})
