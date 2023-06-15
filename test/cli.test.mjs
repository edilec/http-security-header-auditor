/**
 * The command-line surface, and the two shapes exit 2 takes.
 *
 * The report contract makes the distinction explicit: a configuration error
 * means the run never had a subject, so **stdout stays empty**; an input that
 * could not be read means the run had a subject and failed to obtain evidence
 * about it, so stdout carries an `incomplete` report naming the file. A consumer
 * that pipes stdout has to handle both, which is why both are pinned here.
 */

import assert from 'node:assert/strict'
import test from 'node:test'

import { cliHuman, cliReport, cliRun, clean, header, requirement, route, withRoot } from './support.mjs'

test('--help prints usage on stdout and exits 0', async () => {
  const { code, stdout, stderr } = await cliRun(['--help'])

  assert.equal(code, 0)
  assert.equal(stdout.includes('http-security-header-auditor'), true)
  assert.equal(stdout.includes('--as-of YYYY-MM-DD'), true)
  assert.equal(stdout.includes('Nothing is fetched.'), true)
  assert.equal(stderr, '')
})

test('--help documents every exit code and says what a pass means', async () => {
  const { stdout } = await cliRun(['--help'])

  assert.equal(stdout.includes('Exit codes:'), true)
  for (const line of ['  0  ', '  1  ', '  2  ']) assert.equal(stdout.includes(line), true)
  assert.equal(stdout.includes('What a pass means:'), true)
  assert.equal(stdout.includes('Content-Security-Policy-Report-Only never counts as a policy.'), true)
})

test('--version prints the version and exits 0', async () => {
  const { code, stdout } = await cliRun(['--version'])

  assert.equal(code, 0)
  assert.equal(stdout, `0.1.0${String.fromCharCode(0x0a)}`)
})

test('the version the binary prints is the version the manifest declares', async () => {
  const { stdout } = await cliRun(['--version'])
  const manifest = await import('node:fs/promises').then(({ readFile }) =>
    readFile(new URL('../package.json', import.meta.url), 'utf8'))

  assert.equal(stdout.trim(), JSON.parse(manifest).version)
})

test('a missing --root is a configuration error: empty stdout, message on stderr, exit 2', async () => {
  const { code, stdout, stderr } = await cliRun([])

  assert.equal(code, 2)
  assert.equal(stdout, '')
  assert.equal(stderr.includes('--root is required'), true)
})

test('an unknown option is a configuration error, not a finding', async () => {
  const { code, stdout, stderr } = await cliRun(['--root', '.', '--fetch'])

  assert.equal(code, 2)
  assert.equal(stdout, '')
  assert.equal(stderr.includes('Unknown option "--fetch"'), true)
})

test('a flag with no value is a configuration error', async () => {
  const { code, stdout, stderr } = await cliRun(['--root'])

  assert.equal(code, 2)
  assert.equal(stdout, '')
  assert.equal(stderr.includes('--root requires a value'), true)
})

test('an --as-of that is not a calendar date is a configuration error', async () => {
  const { code, stdout, stderr } = await cliReport(clean(), ['--as-of', '2026-02-30'])

  assert.equal(code, 2)
  assert.equal(stdout, '')
  assert.equal(stderr.includes('asOf must be a calendar date written YYYY-MM-DD'), true)
})

test('a root that does not exist is a configuration error, with nothing on stdout', async () => {
  const { code, stdout, stderr } = await cliRun(['--root', '/nonexistent-root-for-this-test'])

  assert.equal(code, 2)
  assert.equal(stdout, '')
  assert.equal(stderr.includes('--root could not be resolved'), true)
})

test('an unreadable input is the other shape: a report on stdout saying which file', async () => {
  const { code, stdout, report } = await cliReport({ 'policy.json': { schemaVersion: '1', required: [{ header: 'x-content-type-options' }] } })

  assert.equal(code, 2)
  assert.notEqual(stdout, '')
  assert.equal(report.status, 'incomplete')
  assert.equal(report.findings.some((finding) => finding.location.file === 'capture.json'), true)
})

test('a clean run exits 0 and prints its summary on stderr', async () => {
  const { code, stdout, stderr, report } = await cliHuman(clean())

  assert.equal(code, 0)
  assert.equal(report.status, 'pass')
  assert.equal(stderr.includes('policy policy.json:'), true)
  assert.equal(stderr.includes('capture capture.json:'), true)
  assert.equal(stderr.includes('status pass'), true)
  assert.equal(stdout.includes('"status": "pass"'), true)
})

test('--json leaves stderr empty on a clean run, so stdout can be piped alone', async () => {
  const { stderr } = await cliReport(clean())

  assert.equal(stderr, '')
})

test('the human summary names the documents that were actually read', async () => {
  const { stderr } = await withRoot({
    'baseline.json': { schemaVersion: '1', required: [{ header: 'x-content-type-options' }] },
    'staging.json': { schemaVersion: '1', routes: [{ id: 'ok', headers: [{ name: 'X-Content-Type-Options', value: 'nosniff' }] }] },
  }, (root) => cliRun(['--root', root, '--policy', 'baseline.json', '--capture', 'staging.json']))

  assert.equal(stderr.includes('policy baseline.json:'), true)
  assert.equal(stderr.includes('capture staging.json:'), true)
})

test('the summary reports the as-of date, or says plainly that none was given', async () => {
  const withDate = await cliHuman(clean(), ['--as-of', '2026-03-01'])
  assert.equal(withDate.stderr.includes('as of 2026-03-01'), true)

  const withoutDate = await cliHuman(clean())
  assert.equal(withoutDate.stderr.includes('as of no date given'), true)
})

test('a failing run exits 1 and the finding is printed with its rule id', async () => {
  const { code, stderr } = await cliHuman({
    'policy.json': { schemaVersion: '1', required: [requirement('x-content-type-options')] },
    'capture.json': { schemaVersion: '1', routes: [route('bare', [])] },
  })

  assert.equal(code, 1)
  assert.equal(stderr.includes('required-header-missing'), true)
  assert.equal(stderr.includes('status fail'), true)
})

test('the tool never writes anything into the root it was pointed at', async () => {
  const { readdir } = await import('node:fs/promises')

  const names = await withRoot(clean(), async (root) => {
    await cliRun(['--root', root])
    return (await readdir(root)).sort()
  })

  assert.deepEqual(names, ['capture.json', 'policy.json'], 'read-only by default means read-only')
})

test('the binary is executable and declares a Node shebang', async () => {
  const { readFile, stat } = await import('node:fs/promises')
  const path = new URL('../bin/http-security-header-auditor.mjs', import.meta.url)

  const text = await readFile(path, 'utf8')
  assert.equal(text.startsWith('#!/usr/bin/env node'), true)

  const info = await stat(path)
  assert.equal((info.mode & 0o111) !== 0, true, 'the bin must be executable')
})

test('a route with a field name that only differs in case is one field, not two', async () => {
  const { code, report } = await cliReport({
    'policy.json': { schemaVersion: '1', required: [requirement('x-content-type-options', { allowedValues: ['nosniff'] })] },
    'capture.json': { schemaVersion: '1', routes: [route('ok', [header('X-CONTENT-TYPE-OPTIONS', 'NOSNIFF')])] },
  })

  assert.equal(code, 0)
  assert.equal(report.status, 'pass')
})
