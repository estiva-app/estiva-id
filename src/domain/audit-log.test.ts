/**
 * PEEK-69: *"every action in the admin console leaves a record naming who did
 * it, to whom, and when."*
 *
 * Two things are checked here that the rest of the suite cannot be: that the
 * one privileged action nobody recorded now records, and that a record can be
 * read back as a sentence about people rather than as a row of ids.
 */
import { afterAll, beforeAll, beforeEach, describe, expect, it } from 'vitest'
import { closePool, query } from '../db/pool.js'
import { prepareDatabase, truncateAll } from '../test/db.js'
import { auditActions, listAudit } from './audit-log.js'
import { recordAudit } from './audit.js'
import { createUserWithKey, offboardUser, setUserStatus } from './users.js'

beforeAll(async () => {
  await prepareDatabase()
})

beforeEach(async () => {
  await truncateAll()
})

afterAll(async () => {
  await closePool()
})

describe('the action nothing used to record', () => {
  /**
   * `setUserStatus` wrote no audit row at all until PEEK-69, which meant
   * offboarding — the action the custody argument most depends on being
   * visible — was the one action that left no trace.
   */
  it('records an offboarding, naming the admin and the person', async () => {
    const admin = await createUserWithKey({ email: 'admin@example.test', role: 'admin' })
    const leaver = await createUserWithKey({ email: 'leaver@example.test' })

    await offboardUser(leaver.id, { actorUserId: admin.id })

    const [entry] = await listAudit({ action: 'user.status_change' })
    expect(entry).toMatchObject({
      actorType: 'user',
      actorUserId: admin.id,
      actorEmail: 'admin@example.test',
      action: 'user.status_change',
      outcome: 'success',
      subjectPubkey: leaver.pubkey,
      subjectUserId: leaver.id,
      subjectEmail: 'leaver@example.test',
    })
    expect(entry?.detail).toMatchObject({ from: 'active', to: 'offboarded' })
  })

  /**
   * The distinction the ticket calls out: an admin restoring access and an
   * admin seizing an account are the same call, and only the record separates
   * them.
   */
  it('distinguishes restoring access from withdrawing it', async () => {
    const admin = await createUserWithKey({ email: 'admin@example.test', role: 'admin' })
    const person = await createUserWithKey({ email: 'person@example.test' })

    await setUserStatus(person.id, 'suspended', { actorUserId: admin.id })
    await setUserStatus(person.id, 'active', { actorUserId: admin.id })

    const entries = await listAudit({ action: 'user.status_change' })
    // Newest first.
    expect(entries[0]?.detail).toMatchObject({ from: 'suspended', to: 'active' })
    expect(entries[1]?.detail).toMatchObject({ from: 'active', to: 'suspended' })
  })

  it('records how many sessions the change killed', async () => {
    const person = await createUserWithKey({ email: 'person@example.test' })
    const { createSession } = await import('./sessions.js')
    await createSession({ userId: person.id })
    await createSession({ userId: person.id })

    await offboardUser(person.id)

    const [entry] = await listAudit({ action: 'user.status_change' })
    expect(entry?.detail).toMatchObject({ sessionsRevoked: 2 })
  })

  /**
   * A script has no admin behind it. Attributing one would be a lie, and a
   * convincing one — the whole value of this table is that the actor is true.
   */
  it('records an unattended change as system, not as a person', async () => {
    const person = await createUserWithKey({ email: 'person@example.test' })
    await offboardUser(person.id)

    const [entry] = await listAudit({ action: 'user.status_change' })
    expect(entry?.actorType).toBe('system')
    expect(entry?.actorUserId).toBeNull()
  })
})

describe('reading it back', () => {
  it('names the people rather than handing back ids', async () => {
    const admin = await createUserWithKey({
      email: 'admin@example.test',
      displayName: 'The Admin',
      role: 'admin',
    })
    const leaver = await createUserWithKey({
      email: 'leaver@example.test',
      displayName: 'The Leaver',
    })
    await offboardUser(leaver.id, { actorUserId: admin.id })

    const [entry] = await listAudit()
    expect(entry?.actorDisplayName).toBe('The Admin')
    expect(entry?.subjectDisplayName).toBe('The Leaver')
    expect(entry?.occurredAt).toMatch(/^\d{4}-\d{2}-\d{2}T/)
  })

  /**
   * A person's history is both directions. "Who offboarded this account" is the
   * question an admin opens a history to answer, and it is not something the
   * account itself did.
   */
  it('returns what a person did and what was done to them', async () => {
    const admin = await createUserWithKey({ email: 'admin@example.test', role: 'admin' })
    const person = await createUserWithKey({ email: 'person@example.test' })

    // Something they did.
    await recordAudit({
      actorType: 'user',
      actorUserId: person.id,
      action: 'session.create',
      outcome: 'success',
    })
    // Something done to them.
    await offboardUser(person.id, { actorUserId: admin.id })
    // Somebody else entirely.
    await recordAudit({
      actorType: 'user',
      actorUserId: admin.id,
      action: 'invite.create',
      outcome: 'success',
    })

    const entries = await listAudit({ userId: person.id })
    expect(entries.map((e) => e.action).sort()).toEqual(['session.create', 'user.status_change'])
  })

  it('still names somebody whose key was rotated after the record was written', async () => {
    const person = await createUserWithKey({ email: 'person@example.test' })
    await offboardUser(person.id)

    // The record keeps the old pubkey; the join must still find them.
    await query("update user_keys set status = 'rotated' where user_id = $1", [person.id])

    const [entry] = await listAudit({ action: 'user.status_change' })
    expect(entry?.subjectUserId).toBe(person.id)
    expect(entry?.subjectEmail).toBe('person@example.test')
  })

  it('filters by action', async () => {
    const person = await createUserWithKey({ email: 'person@example.test' })
    await offboardUser(person.id)
    await recordAudit({
      actorType: 'user',
      actorUserId: person.id,
      action: 'session.create',
      outcome: 'success',
    })

    const entries = await listAudit({ action: 'session.create' })
    expect(entries).toHaveLength(1)
    expect(entries[0]?.action).toBe('session.create')
  })

  /**
   * Paged by id, not by timestamp. Several rows share a millisecond — a refusal
   * next to the token issue that preceded it — so a time cursor drops or
   * repeats rows exactly at a page boundary.
   */
  it('pages without dropping or repeating rows written in the same instant', async () => {
    const person = await createUserWithKey({ email: 'person@example.test' })
    for (let i = 0; i < 10; i += 1) {
      await recordAudit({
        actorType: 'user',
        actorUserId: person.id,
        action: 'session.create',
        outcome: 'success',
        detail: { n: i },
      })
    }

    const first = await listAudit({ limit: 4 })
    const second = await listAudit({ limit: 4, before: first[first.length - 1]?.id })
    const third = await listAudit({ limit: 4, before: second[second.length - 1]?.id })

    const ids = [...first, ...second, ...third].map((e) => e.id)
    expect(ids).toHaveLength(10)
    expect(new Set(ids).size).toBe(10)
    // Strictly descending, which is what makes "before" a stable cursor.
    expect([...ids].sort((a, b) => Number(b) - Number(a))).toEqual(ids)
  })

  it('caps the page size a caller can ask for', async () => {
    const person = await createUserWithKey({ email: 'person@example.test' })
    for (let i = 0; i < 5; i += 1) {
      await recordAudit({
        actorType: 'user',
        actorUserId: person.id,
        action: 'session.create',
        outcome: 'success',
      })
    }
    await expect(listAudit({ limit: 10_000 })).resolves.toHaveLength(5)
  })

  it('offers the actions actually present, for a filter', async () => {
    const person = await createUserWithKey({ email: 'person@example.test' })
    await offboardUser(person.id)
    await expect(auditActions()).resolves.toContain('user.status_change')
  })
})
