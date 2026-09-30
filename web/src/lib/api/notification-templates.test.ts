import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest'
import { ApiError } from './client'
import { notificationTemplatesApi, templateValidationError } from './notification-templates'

describe('notification template API', () => {
  beforeEach(() => {
    vi.spyOn(globalThis, 'fetch')
  })
  afterEach(() => vi.restoreAllMocks())
  function respond(body: unknown, status = 200) {
    vi.mocked(fetch).mockResolvedValueOnce({ ok: status < 400, status, json: async () => body } as Response)
  }

  it('sends the filters and follows full pages with after', async () => {
    const page = Array.from({ length: 500 }, (_, index) => ({ id: `t${String(index).padStart(3, '0')}` }))
    respond({ items: page })
    respond({ items: [{ id: 'last' }] })
    const items = await notificationTemplatesApi.listNotificationTemplates({ event_type: '*', family: 'chat', status: 'draft' })
    expect(items).toHaveLength(501)
    const first = new URL(String(vi.mocked(fetch).mock.calls[0][0]), 'http://x')
    expect(first.pathname).toBe('/api/v1/notifications/templates')
    expect(Object.fromEntries(first.searchParams)).toEqual({ event_type: '*', family: 'chat', status: 'draft', limit: '500' })
    const second = new URL(String(vi.mocked(fetch).mock.calls[1][0]), 'http://x')
    expect(second.searchParams.get('after')).toBe('t499')
  })

  it('posts activate, rollback and archive with the revision', async () => {
    respond({ id: 'a/b' })
    await notificationTemplatesApi.rollbackNotificationTemplate('a/b', { revision: 4, version: 1 })
    const [url, options] = vi.mocked(fetch).mock.calls[0]
    expect(String(url)).toContain('/notifications/templates/a%2Fb/rollback')
    expect(options).toMatchObject({ method: 'POST', body: JSON.stringify({ revision: 4, version: 1 }) })
  })

  it('has no built-ins until #1366 ships, without calling the API', async () => {
    expect(await notificationTemplatesApi.listBuiltinNotificationTemplates()).toEqual([])
    expect(fetch).not.toHaveBeenCalled()
  })

  it('reads the structured body of an engine rejection', () => {
    const error = new ApiError(400, 'bad', { error: 'bad', field: 'body', event_type: '*', code: 'parse_error', line: 3 })
    expect(templateValidationError(error)).toEqual({ error: 'bad', field: 'body', event_type: '*', code: 'parse_error', line: 3 })
    expect(templateValidationError(new ApiError(400, 'plain', { error: 'plain' }))).toEqual({
      error: 'plain', field: undefined, event_type: undefined, code: undefined, line: undefined,
    })
    expect(templateValidationError(new ApiError(409, 'stale'))).toBeNull()
  })
})
