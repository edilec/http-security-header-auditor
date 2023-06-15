/**
 * The shipped examples, run as the README says to run them.
 *
 * An example that has drifted from the tool is worse than no example: it is the
 * first thing a reader tries and the last thing anybody checks. These cases
 * assert the exact exit code and the exact shape of each one, so a change in the
 * rules that leaves the examples stale fails the build.
 */

import assert from 'node:assert/strict'
import { readFile } from 'node:fs/promises'
import { join } from 'node:path'
import test from 'node:test'

import { CLI, cliRun, projectDirectory } from './support.mjs'

const AS_OF = '2026-03-01'

async function runExample(name) {
  const result = await cliRun(['--root', join(projectDirectory, 'examples', name), '--as-of', AS_OF, '--json'])
  return { ...result, report: JSON.parse(result.stdout) }
}

test('the clean example exits 0 with one applied waiver and no error', async () => {
  const { code, report } = await runExample('clean')

  assert.equal(report.status, 'pass')
  assert.equal(code, 0)
  assert.equal(report.summary.errors, 0)
  assert.equal(report.summary.warnings, 0)
  assert.equal(report.summary.routes, 3)
  assert.equal(report.summary.evaluated, 3)
  assert.equal(report.summary.undecided, 0)
  assert.equal(report.summary.exceptionsApplied, 1)
  assert.deepEqual(report.findings.map((finding) => finding.ruleId), ['exception-applied'])
})

test('the clean example still records that the waived route enforces no policy', async () => {
  const { report } = await runExample('clean')
  const waived = report.routes.find((row) => row.id === 'legacy-report-viewer')

  assert.equal(waived.verdict, 'waived')
  assert.equal(waived.csp.enforced, false)
  assert.equal(waived.csp.reportOnly, true)
  assert.deepEqual(waived.missing, ['content-security-policy'])
})

test('the broken example exits 1 -- a decided failure, not an incomplete run', async () => {
  const { code, report } = await runExample('broken')

  assert.equal(report.status, 'fail')
  assert.equal(code, 1)
  assert.equal(report.summary.undecided, 0, 'every field in this capture was readable')
  assert.equal(report.summary.routesFailing, 2)
  assert.equal(report.summary.exceptionsExpired, 1)
})

test('the broken example demonstrates each family of rule the tool has', async () => {
  const { report } = await runExample('broken')
  const raised = new Set(report.findings.map((finding) => finding.ruleId))

  for (const ruleId of [
    'csp-directive-duplicate',
    'csp-directive-missing',
    'csp-none-with-sources',
    'csp-report-only-without-enforcement',
    'csp-source-forbidden',
    'csp-unsafe-inline-with-nonce',
    'csp-wildcard-shadows-sources',
    'exception-expired',
    'exception-route-unknown',
    'forbidden-header-present',
    'header-value-unexpected',
    'hsts-include-subdomains-missing',
    'hsts-max-age-too-short',
    'required-header-missing',
  ]) {
    assert.equal(raised.has(ruleId), true, `the broken example no longer raises ${ruleId}`)
  }
})

test('the incomplete example exits 2 and reports gaps rather than verdicts', async () => {
  const { code, report } = await runExample('incomplete')

  assert.equal(report.status, 'incomplete')
  assert.equal(code, 2)
  assert.equal(report.summary.routesUndecided, 2)
  assert.equal(report.summary.undecided, 2)
  assert.deepEqual(report.routes.map((row) => row.verdict), ['undecided', 'undecided'])

  const raised = new Set(report.findings.map((finding) => finding.ruleId))
  assert.equal(raised.has('header-duplicated'), true)
  assert.equal(raised.has('csp-analysis-incomplete'), true)
})

test('the example script in the manifest is the clean example, and it exits 0', async () => {
  const manifest = JSON.parse(await readFile(join(projectDirectory, 'package.json'), 'utf8'))

  assert.equal(manifest.scripts.example.includes('--root examples/clean'), true)
  assert.equal(manifest.scripts.example.includes(`--as-of ${AS_OF}`), true)
  assert.equal(manifest.scripts.example.includes(CLI.slice(CLI.lastIndexOf('bin/'))), true)

  const { code } = await cliRun(['--root', 'examples/clean', '--as-of', AS_OF])
  assert.equal(code, 0)
})

test('every example carries both documents and no other file', async () => {
  const { readdir } = await import('node:fs/promises')

  for (const name of ['broken', 'clean', 'incomplete']) {
    const entries = (await readdir(join(projectDirectory, 'examples', name))).sort()
    assert.deepEqual(entries, ['capture.json', 'policy.json'], `examples/${name}`)
  }
})

test('no example contains anything resembling a real credential or a real host', async () => {
  for (const name of ['broken', 'clean', 'incomplete']) {
    for (const file of ['capture.json', 'policy.json']) {
      const text = await readFile(join(projectDirectory, 'examples', name, file), 'utf8')

      // RFC 2606 reserves .invalid for exactly this. A real hostname in an
      // example is an invitation to point the tool at it.
      for (const host of text.match(/https?:\/\/[^\s"';]+/g) ?? []) {
        assert.match(host, /\.invalid(\/|$)/, `${name}/${file} names ${host}`)
      }
      assert.equal(/AKIA[0-9A-Z]{16}/.test(text), false, `${name}/${file} carries something shaped like an access key`)
      assert.equal(/-----BEGIN [A-Z ]*PRIVATE KEY-----/.test(text), false)
    }
  }
})
