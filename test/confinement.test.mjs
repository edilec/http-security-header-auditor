/**
 * Path confinement, and the false refusals a careless confinement causes.
 *
 * Rejecting `..` and absolute paths is not confinement: a symbolic link planted
 * inside the declared root contains no `..` at all and points anywhere. Equally,
 * comparing a real root against an unresolved target refuses legitimate files
 * whenever the root itself is reached through a link -- which on macOS is the
 * ordinary case, because the system temporary directory is one. Both halves are
 * tested here, because a tool that refuses valid work is broken too.
 */

import assert from 'node:assert/strict'
import { mkdir, mkdtemp, rm, symlink, writeFile } from 'node:fs/promises'
import { tmpdir } from 'node:os'
import { join } from 'node:path'
import test from 'node:test'

import { auditHeaders, isInside } from '../src/index.mjs'
import { clean, findingsFor, raisedRules } from './support.mjs'

const POLICY = { schemaVersion: '1', required: [{ header: 'x-content-type-options' }] }
const CAPTURE = { schemaVersion: '1', routes: [{ id: 'ok', headers: [{ name: 'X-Content-Type-Options', value: 'nosniff' }] }] }

async function withTree(body) {
  const base = await mkdtemp(join(tmpdir(), 'http-security-header-auditor-tree-'))
  try {
    const root = join(base, 'root')
    const outside = join(base, 'outside')
    await mkdir(root)
    await mkdir(outside)
    return await body({ base, root, outside })
  } finally {
    await rm(base, { recursive: true, force: true })
  }
}

test('isInside accepts the root itself and everything beneath it, and nothing beside it', () => {
  assert.equal(isInside('/a/b', '/a/b'), true)
  assert.equal(isInside('/a/b', '/a/b/c'), true)
  assert.equal(isInside('/a/b', '/a/bc'), false)
  assert.equal(isInside('/a/b', '/a'), false)
  assert.equal(isInside('/', '/a'), true)
})

test('a symbolic link inside the root that points out of it is refused unread', async () => {
  await withTree(async ({ root, outside }) => {
    await writeFile(join(root, 'capture.json'), JSON.stringify(CAPTURE))
    await writeFile(join(outside, 'secret-policy.json'), JSON.stringify(POLICY))
    await symlink(join(outside, 'secret-policy.json'), join(root, 'policy.json'))

    const report = await auditHeaders({ root })

    assert.equal(report.status, 'incomplete')
    assert.deepEqual(findingsFor(report, 'path-escapes-root').map((finding) => finding.location.file), ['policy.json'])
    assert.equal(report.summary.checked, 0)
  })
})

test('the content of a file outside the root never reaches the report', async () => {
  await withTree(async ({ root, outside }) => {
    await writeFile(join(root, 'policy.json'), JSON.stringify(POLICY))
    await writeFile(join(outside, 'elsewhere.json'), JSON.stringify({
      schemaVersion: '1',
      routes: [{ id: 'leaked-route-name', headers: [] }],
    }))
    await symlink(join(outside, 'elsewhere.json'), join(root, 'capture.json'))

    const report = await auditHeaders({ root })

    assert.equal(JSON.stringify(report).includes('leaked-route-name'), false)
  })
})

test('a symbolic link that stays inside the root is followed, because it is inside the root', async () => {
  await withTree(async ({ root }) => {
    await mkdir(join(root, 'exports'))
    await writeFile(join(root, 'exports', 'real-capture.json'), JSON.stringify(CAPTURE))
    await writeFile(join(root, 'policy.json'), JSON.stringify(POLICY))
    await symlink(join(root, 'exports', 'real-capture.json'), join(root, 'capture.json'))

    const report = await auditHeaders({ root })

    assert.equal(report.status, 'pass')
    assert.equal(report.summary.checked, 1)
  })
})

test('a root reached through a symbolic link is not a reason to refuse anything', async () => {
  await withTree(async ({ base, root }) => {
    await writeFile(join(root, 'policy.json'), JSON.stringify(POLICY))
    await writeFile(join(root, 'capture.json'), JSON.stringify(CAPTURE))
    const linkedRoot = join(base, 'linked-root')
    await symlink(root, linkedRoot)

    const report = await auditHeaders({ root: linkedRoot })

    assert.equal(report.status, 'pass', 'both sides are resolved, so a linked root is the same root')
  })
})

test('a subdirectory of the root is a legitimate place for an input', async () => {
  await withTree(async ({ root }) => {
    await mkdir(join(root, 'nested'))
    await writeFile(join(root, 'nested', 'policy.json'), JSON.stringify(POLICY))
    await writeFile(join(root, 'capture.json'), JSON.stringify(CAPTURE))

    const report = await auditHeaders({ root, policy: 'nested/policy.json' })

    assert.equal(report.status, 'pass')
  })
})

test('an absolute name, a name stepping out with .., and a name carrying a control are all usage errors', async () => {
  await withTree(async ({ root }) => {
    await writeFile(join(root, 'policy.json'), JSON.stringify(POLICY))
    await writeFile(join(root, 'capture.json'), JSON.stringify(CAPTURE))

    await assert.rejects(() => auditHeaders({ root, policy: '/etc/passwd' }), /must be relative to --root/)
    await assert.rejects(() => auditHeaders({ root, policy: '../outside/policy.json' }), /must not step outside/)
    await assert.rejects(() => auditHeaders({ root, capture: `a${String.fromCharCode(0x0a)}b.json` }), /control, separator or bidi/)
    await assert.rejects(() => auditHeaders({ root, capture: '' }), /relative file name/)
  })
})

test('a directory where a document should be is unreadable evidence, not an empty document', async () => {
  await withTree(async ({ root }) => {
    await writeFile(join(root, 'policy.json'), JSON.stringify(POLICY))
    await mkdir(join(root, 'capture.json'))

    const report = await auditHeaders({ root })

    assert.equal(report.status, 'incomplete')
    assert.equal(findingsFor(report, 'input-unreadable')[0].message.includes('not a regular file'), true)
  })
})

test('a root that is a file, or does not exist, is a configuration error rather than a report', async () => {
  await withTree(async ({ base, root }) => {
    await writeFile(join(root, 'policy.json'), JSON.stringify(POLICY))

    await assert.rejects(() => auditHeaders({ root: join(root, 'policy.json') }), /--root must be a directory/)
    await assert.rejects(() => auditHeaders({ root: join(base, 'nowhere') }), /--root could not be resolved/)
  })
})

test('a dangling link inside the root is reported as unreadable, not as an escape', async () => {
  await withTree(async ({ root }) => {
    await writeFile(join(root, 'capture.json'), JSON.stringify(CAPTURE))
    await symlink(join(root, 'never-written.json'), join(root, 'policy.json'))

    const report = await auditHeaders({ root })

    assert.equal(report.status, 'incomplete')
    assert.equal(raisedRules(report).includes('input-unreadable'), true)
  })
})

test('the ordinary case -- two plain files in a plain directory -- still works', async () => {
  const report = await (async () => {
    const files = clean()
    const base = await mkdtemp(join(tmpdir(), 'http-security-header-auditor-plain-'))
    try {
      for (const [name, content] of Object.entries(files)) {
        await writeFile(join(base, name), JSON.stringify(content))
      }
      return await auditHeaders({ root: base })
    } finally {
      await rm(base, { recursive: true, force: true })
    }
  })()

  assert.equal(report.status, 'pass')
})
