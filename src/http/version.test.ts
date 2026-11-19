/**
 * `/version.json` is what a check after a deploy waits on: it must name the
 * commit the running image was built from, and nothing between it and the
 * reader may keep an old answer.
 */
import { afterEach, describe, expect, it } from 'vitest'
import { createApp } from './app.js'

const app = createApp()

afterEach(() => {
  Reflect.deleteProperty(process.env, 'RELEASE')
})

describe('GET /version.json', () => {
  it('names the commit the image was built from, uncached', async () => {
    process.env.RELEASE = 'c0ffee1234abcd5678'
    const response = await app.request('/version.json')
    expect(response.status).toBe(200)
    expect(response.headers.get('cache-control')).toBe('no-store')
    expect(await response.json()).toEqual({ app: 'estiva-id', commit: 'c0ffee1234abcd5678' })
  })

  it('says unknown when the image carries no commit', async () => {
    const response = await app.request('/version.json')
    expect(await response.json()).toEqual({ app: 'estiva-id', commit: 'unknown' })
  })

  it('answers JSON to a browser too, not the account UI', async () => {
    process.env.RELEASE = 'c0ffee1234abcd5678'
    const response = await app.request('/version.json', { headers: { accept: 'text/html' } })
    expect(response.headers.get('content-type')).toContain('application/json')
    expect(await response.json()).toEqual({ app: 'estiva-id', commit: 'c0ffee1234abcd5678' })
  })
})
