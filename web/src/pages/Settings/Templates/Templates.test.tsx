import { act, fireEvent, render, screen, waitFor, within } from '@testing-library/react'
import { MemoryRouter, Route, Routes } from 'react-router-dom'
import { beforeEach, describe, expect, it, vi } from 'vitest'
import { api, ApiError, type NotificationTemplate, type NotificationTemplateDetail, type NotificationTemplateVersion } from '../../../lib/api'
import type { NotificationEventSpec } from '../../../lib/api/notifications'
import { resetCapabilityCache } from '../../../lib/capabilities'
import { STALE_MESSAGE, TemplateEditor } from './TemplateEditor'
import { TemplateLibrary } from './TemplateLibrary'

vi.mock('../../../lib/api', async (original) => ({
  ...(await original<typeof import('../../../lib/api')>()),
  api: {
    me: vi.fn(),
    listCapabilities: vi.fn(),
    listNotificationEventTypes: vi.fn(),
    listBuiltinNotificationTemplates: vi.fn(),
    listNotificationTemplates: vi.fn(),
    getNotificationTemplate: vi.fn(),
    listNotificationTemplateVersions: vi.fn(),
    createNotificationTemplate: vi.fn(),
    updateNotificationTemplate: vi.fn(),
    activateNotificationTemplate: vi.fn(),
    rollbackNotificationTemplate: vi.fn(),
    archiveNotificationTemplate: vi.fn(),
  },
}))

const CATALOG = [
  {
    type: 'incident.created',
    label: 'Incident created',
    variables: [
      { name: 'title', class: 'signal', description: 'Incident title', list_cap: 0 },
      { name: 'affected_assets', class: 'summary', description: 'Assets the incident touches', list_cap: 50 },
    ],
  },
  { type: 'vulnerability_action.created', label: 'Vulnerability action created', variables: [] },
] as unknown as NotificationEventSpec[]

function head(overrides: Partial<NotificationTemplate> = {}): NotificationTemplate {
  return {
    tenant_id: 't1',
    id: 'tpl-1',
    name: 'Incident chat',
    event_type: 'incident.created',
    family: 'chat',
    locale: 'en',
    status: 'active',
    latest_version: 2,
    active_version: 2,
    revision: 3,
    created_at: '2026-09-01T00:00:00Z',
    created_by: 'alice',
    updated_at: '2026-09-02T00:00:00Z',
    updated_by: 'alice',
    ...overrides,
  }
}

function version(number: number, fields: Record<string, string>): NotificationTemplateVersion {
  return { tenant_id: 't1', template_id: 'tpl-1', version: number, fields, checksum: `c${number}`, created_at: '2026-09-02T00:00:00Z', created_by: 'alice' }
}

const V1 = version(1, { title: 'Old title', body: 'Old body' })
const V2 = version(2, { title: 'Incident', body: 'Opened' })
const DETAIL: NotificationTemplateDetail = { ...head(), latest: V2, active: V2 }

function renderAt(path: string, state?: unknown) {
  return render(
    <MemoryRouter initialEntries={[{ pathname: path, state }]}>
      <Routes>
        <Route path="/settings/templates" element={<TemplateLibrary />} />
        <Route path="/settings/templates/new" element={<TemplateEditor />} />
        <Route path="/settings/templates/:id" element={<TemplateEditor />} />
      </Routes>
    </MemoryRouter>,
  )
}

// The base TextArea's label carries a visually hidden required marker that jsdom, without CSS, keeps
// in the accessible name, so content fields are found by a name prefix.
const fieldName = (label: string) => new RegExp(`^${label}\\b`)
const findField = (label: string) => screen.findByRole('textbox', { name: fieldName(label) })
const getField = (label: string) => screen.getByRole('textbox', { name: fieldName(label) })
const queryField = (label: string) => screen.queryByRole('textbox', { name: fieldName(label) })

beforeEach(() => {
  vi.resetAllMocks()
  resetCapabilityCache()
  // Radix Select scrolls the chosen option into view, which jsdom does not implement.
  Object.defineProperty(HTMLElement.prototype, 'scrollIntoView', { configurable: true, value: vi.fn() })
  vi.mocked(api.me).mockResolvedValue({ role: 'integration_admin' } as never)
  vi.mocked(api.listCapabilities).mockResolvedValue(null as never)
  vi.mocked(api.listNotificationEventTypes).mockResolvedValue(CATALOG)
  vi.mocked(api.listBuiltinNotificationTemplates).mockResolvedValue([])
  vi.mocked(api.listNotificationTemplates).mockResolvedValue([])
  vi.mocked(api.getNotificationTemplate).mockResolvedValue(DETAIL)
  vi.mocked(api.listNotificationTemplateVersions).mockResolvedValue([V2, V1])
})

describe('template library', () => {
  it('lists custom templates by event type, then family, with status, language and versions', async () => {
    vi.mocked(api.listNotificationTemplates).mockResolvedValue([
      head(),
      head({ id: 'tpl-2', name: 'Incident email', family: 'email', status: 'draft', active_version: 0, latest_version: 1 }),
      head({ id: 'tpl-3', name: 'Everything', event_type: '*', family: 'webhook', locale: '*', status: 'archived', latest_version: 4, active_version: 3 }),
    ])
    renderAt('/settings/templates')

    const incident = await screen.findByRole('region', { name: 'Incident created' })
    expect(within(incident).getByRole('link', { name: 'Incident chat' })).toHaveAttribute('href', '/settings/templates/tpl-1')
    expect(within(incident).getByText('Chat')).toBeInTheDocument()
    expect(within(incident).getByText('Email')).toBeInTheDocument()
    expect(within(incident).getByText(/Latest v1 · never activated/)).toBeInTheDocument()
    expect(within(incident).getByText('Draft')).toBeInTheDocument()

    const any = screen.getByRole('region', { name: 'Any event (*)' })
    expect(within(any).getByText('Archived')).toBeInTheDocument()
    expect(within(any).getByText('Any language (*)')).toBeInTheDocument()
    expect(within(any).getByText(/Latest v4 · renders v3/)).toBeInTheDocument()
    // `*` is listed before concrete event types.
    const regions = screen.getAllByRole('region').map((region) => region.getAttribute('aria-label'))
    expect(regions.indexOf('Any event (*)')).toBeLessThan(regions.indexOf('Incident created'))

    expect(screen.getByRole('link', { name: 'New template' })).toHaveAttribute('href', '/settings/templates/new')
  })

  it('explains that built-ins arrive later and that there are no custom templates yet', async () => {
    renderAt('/settings/templates')
    expect(await screen.findByText('Built-in defaults are not available in this build yet')).toBeInTheDocument()
    expect(await screen.findByText('No custom templates yet')).toBeInTheDocument()
  })

  it('passes the status filter to the API', async () => {
    renderAt('/settings/templates')
    await screen.findByText('No custom templates yet')
    fireEvent.click(screen.getByRole('combobox', { name: 'Filter by status' }))
    fireEvent.click(await screen.findByRole('option', { name: 'Draft' }))
    await waitFor(() => expect(api.listNotificationTemplates).toHaveBeenLastCalledWith({ event_type: undefined, family: undefined, status: 'draft' }))
    expect(await screen.findByText('No templates match these filters')).toBeInTheDocument()
  })

  it('shows an error with a retry that loads again', async () => {
    vi.mocked(api.listNotificationTemplates).mockRejectedValueOnce(new ApiError(500, 'boom')).mockResolvedValueOnce([head()])
    renderAt('/settings/templates')
    expect(await screen.findByText('Could not load templates: boom')).toBeInTheDocument()
    fireEvent.click(screen.getByRole('button', { name: 'Retry' }))
    expect(await screen.findByRole('link', { name: 'Incident chat' })).toBeInTheDocument()
  })

  it('clones a built-in into a pre-filled draft', async () => {
    vi.mocked(api.listBuiltinNotificationTemplates).mockResolvedValue([
      { event_type: 'incident.created', family: 'email', locale: 'vi', fields: { subject: 'Sự cố mới', body: 'Mở bảng điều khiển' } },
    ])
    vi.mocked(api.createNotificationTemplate).mockResolvedValue({ ...DETAIL, id: 'tpl-new', family: 'email', locale: 'vi', status: 'draft' })
    renderAt('/settings/templates')

    fireEvent.click(await screen.findByRole('button', { name: 'Clone Incident created · Email · Vietnamese' }))

    expect(await screen.findByRole('heading', { name: 'New template' })).toBeInTheDocument()
    expect(screen.getByText('Cloned from the built-in default. Save to create your draft.')).toBeInTheDocument()
    await waitFor(() => expect(screen.getByRole('combobox', { name: 'Event' })).toHaveTextContent('Incident created'))
    expect(screen.getByRole('combobox', { name: 'Channel family' })).toHaveTextContent('Email')
    expect(screen.getByRole('combobox', { name: 'Language' })).toHaveTextContent('Vietnamese')
    expect(getField('Subject')).toHaveValue('Sự cố mới')
    expect(getField('Body')).toHaveValue('Mở bảng điều khiển')

    fireEvent.click(screen.getByRole('button', { name: 'Create draft' }))
    await waitFor(() =>
      expect(api.createNotificationTemplate).toHaveBeenCalledWith({
        name: 'Custom incident.created email (vi)',
        event_type: 'incident.created',
        family: 'email',
        locale: 'vi',
        fields: { subject: 'Sự cố mới', body: 'Mở bảng điều khiển' },
      }),
    )
  })

  it('shows the permission state and no controls to a user without manage_integrations', async () => {
    vi.mocked(api.me).mockResolvedValue({ role: 'member' } as never)
    renderAt('/settings/templates')
    expect(await screen.findByText('Administrator access required')).toBeInTheDocument()
    expect(screen.queryByRole('link', { name: 'New template' })).not.toBeInTheDocument()
    expect(api.listNotificationTemplates).not.toHaveBeenCalled()
  })

  it('shows the permission state when the API answers 403', async () => {
    vi.mocked(api.listNotificationTemplates).mockRejectedValue(new ApiError(403, 'forbidden'))
    renderAt('/settings/templates')
    expect(await screen.findByText('Administrator access required')).toBeInTheDocument()
    expect(screen.queryByRole('link', { name: 'New template' })).not.toBeInTheDocument()
  })
})

describe('template editor', () => {
  it('creates a draft with the key and the family fields', async () => {
    vi.mocked(api.createNotificationTemplate).mockResolvedValue({ ...DETAIL, id: 'tpl-new', status: 'draft' })
    renderAt('/settings/templates/new')
    fireEvent.change(await screen.findByLabelText('Name'), { target: { value: 'Incident pager' } })
    fireEvent.click(screen.getByRole('combobox', { name: 'Event' }))
    fireEvent.click(await screen.findByRole('option', { name: 'Incident created' }))
    fireEvent.click(screen.getByRole('combobox', { name: 'Channel family' }))
    fireEvent.click(await screen.findByRole('option', { name: 'Pager' }))
    expect(queryField('Body')).not.toBeInTheDocument()
    fireEvent.change(getField('Summary'), { target: { value: 'Incident opened' } })
    fireEvent.click(screen.getByRole('button', { name: 'Create draft' }))

    await waitFor(() =>
      expect(api.createNotificationTemplate).toHaveBeenCalledWith({
        name: 'Incident pager',
        event_type: 'incident.created',
        family: 'pager',
        locale: 'en',
        fields: { summary: 'Incident opened' },
      }),
    )
    // The editor moves to the created template.
    await waitFor(() => expect(api.getNotificationTemplate).toHaveBeenCalledWith('tpl-new'))
    expect(await screen.findByText('Draft created as version 1. Activate it to make it render.')).toBeInTheDocument()
  })

  it('refuses an unnamed or empty template before calling the API', async () => {
    renderAt('/settings/templates/new')
    fireEvent.click(await screen.findByRole('button', { name: 'Create draft' }))
    expect(await screen.findByText('Enter a name.')).toBeInTheDocument()
    expect(screen.getByText('Write at least one field.')).toBeInTheDocument()
    expect(api.createNotificationTemplate).not.toHaveBeenCalled()
  })

  it('saves an edit as a new version with the revision it read', async () => {
    vi.mocked(api.updateNotificationTemplate).mockResolvedValue({ ...DETAIL, latest_version: 3, revision: 4, latest: version(3, { title: 'Incident', body: 'Opened now' }) })
    renderAt('/settings/templates/tpl-1')
    const body = await findField('Body')
    expect(body).toHaveValue('Opened')
    fireEvent.change(body, { target: { value: 'Opened now' } })
    fireEvent.click(screen.getByRole('button', { name: 'Save new version' }))
    await waitFor(() =>
      expect(api.updateNotificationTemplate).toHaveBeenCalledWith('tpl-1', {
        name: undefined,
        fields: { title: 'Incident', body: 'Opened now' },
        revision: 3,
      }),
    )
    expect(await screen.findByText(/Saved version 3/)).toBeInTheDocument()
  })

  it('places an engine rejection on the field it names, with the line', async () => {
    vi.mocked(api.updateNotificationTemplate).mockRejectedValue(
      new ApiError(400, 'template field "body" is invalid for event type incident.created: unknown_variable at line 2: nope', {
        error: 'template field "body" is invalid for event type incident.created: unknown_variable at line 2: nope',
        field: 'body',
        event_type: 'incident.created',
        code: 'unknown_variable',
        line: 2,
      }),
    )
    renderAt('/settings/templates/tpl-1')
    const body = await findField('Body')
    fireEvent.change(body, { target: { value: 'Opened\n{{.nope}}' } })
    fireEvent.click(screen.getByRole('button', { name: 'Save new version' }))

    const message = await screen.findByText(/^Line 2 · unknown_variable: template field "body"/)
    expect(body).toHaveAttribute('aria-invalid', 'true')
    expect(body.getAttribute('aria-describedby')).toContain(message.id)
    expect(getField('Title')).not.toHaveAttribute('aria-invalid')
    expect(screen.queryByRole('alert')).not.toBeInTheDocument()
    // Editing the field clears its error.
    fireEvent.change(body, { target: { value: 'Opened' } })
    expect(screen.queryByText(/^Line 2/)).not.toBeInTheDocument()
  })

  it('reloads on a stale revision, keeps the text and tells the user', async () => {
    vi.mocked(api.updateNotificationTemplate).mockRejectedValue(new ApiError(409, 'stale revision'))
    vi.mocked(api.getNotificationTemplate).mockResolvedValueOnce(DETAIL).mockResolvedValueOnce({ ...DETAIL, revision: 5 })
    renderAt('/settings/templates/tpl-1')
    const body = await findField('Body')
    fireEvent.change(body, { target: { value: 'Mine' } })
    fireEvent.click(screen.getByRole('button', { name: 'Save new version' }))

    expect(await screen.findByText(STALE_MESSAGE)).toBeInTheDocument()
    expect(api.getNotificationTemplate).toHaveBeenCalledTimes(2)
    expect(body).toHaveValue('Mine')

    vi.mocked(api.updateNotificationTemplate).mockResolvedValue({ ...DETAIL, revision: 6, latest_version: 3 })
    fireEvent.click(screen.getByRole('button', { name: 'Save new version' }))
    await waitFor(() => expect(api.updateNotificationTemplate).toHaveBeenLastCalledWith('tpl-1', expect.objectContaining({ revision: 5 })))
  })

  it('activates the latest version and rolls back to an earlier one', async () => {
    const draft: NotificationTemplateDetail = { ...DETAIL, status: 'draft', active_version: 0, active: undefined }
    vi.mocked(api.getNotificationTemplate).mockResolvedValue(draft)
    vi.mocked(api.activateNotificationTemplate).mockResolvedValue({ ...DETAIL, revision: 4, archived_template_id: 'tpl-old' })
    vi.mocked(api.rollbackNotificationTemplate).mockResolvedValue({ ...DETAIL, revision: 5, active_version: 1 })
    renderAt('/settings/templates/tpl-1')

    fireEvent.click(await screen.findByRole('button', { name: 'Activate v2' }))
    await waitFor(() => expect(api.activateNotificationTemplate).toHaveBeenCalledWith('tpl-1', { revision: 3, version: 2 }))
    expect(await screen.findByText(/Version 2 now renders\. The template that was active/)).toBeInTheDocument()
    expect(screen.getByRole('button', { name: 'Activate v2' })).toBeDisabled()

    fireEvent.click(screen.getByRole('button', { name: 'Roll back to v1' }))
    await waitFor(() => expect(api.rollbackNotificationTemplate).toHaveBeenCalledWith('tpl-1', { revision: 4, version: 1 }))
    expect(await screen.findByText('Version 1 now renders.')).toBeInTheDocument()
  })

  it('archives with the revision it read', async () => {
    vi.mocked(api.archiveNotificationTemplate).mockResolvedValue({ ...DETAIL, status: 'archived', revision: 4 })
    renderAt('/settings/templates/tpl-1')
    fireEvent.click(await screen.findByRole('button', { name: 'Archive' }))
    await waitFor(() => expect(api.archiveNotificationTemplate).toHaveBeenCalledWith('tpl-1', { revision: 3 }))
    expect(await screen.findByText(/^Archived\./)).toBeInTheDocument()
  })

  it('inserts a variable at the cursor of the focused field', async () => {
    renderAt('/settings/templates/tpl-1')
    const title = await findField('Title')
    expect(title).toHaveValue('Incident')
    act(() => {
      ;(title as HTMLTextAreaElement).focus()
      ;(title as HTMLTextAreaElement).setSelectionRange(0, 0)
    })
    fireEvent.click(screen.getByRole('button', { name: 'Insert title' }))
    expect(title).toHaveValue('{{.title}}Incident')
    expect(screen.getByRole('button', { name: 'Insert affected_assets' })).toHaveTextContent('≤ 50')
  })

  it('explains an event without variables', async () => {
    vi.mocked(api.getNotificationTemplate).mockResolvedValue({ ...DETAIL, event_type: 'vulnerability_action.created' })
    renderAt('/settings/templates/tpl-1')
    expect(await screen.findByText('This event does not expose template variables yet')).toBeInTheDocument()
  })

  it('offers a * template only the variables every event declares', async () => {
    renderAt('/settings/templates/new')
    // The default key is `*`; the second catalog event declares none, so nothing is shared.
    expect(await screen.findByText('This event does not expose template variables yet')).toBeInTheDocument()
    fireEvent.click(screen.getByRole('combobox', { name: 'Event' }))
    fireEvent.click(await screen.findByRole('option', { name: 'Incident created' }))
    expect(await screen.findByRole('button', { name: 'Insert title' })).toBeInTheDocument()
  })

  it('shows a missing template as not found', async () => {
    vi.mocked(api.getNotificationTemplate).mockRejectedValue(new ApiError(404, 'not found'))
    renderAt('/settings/templates/tpl-x')
    expect(await screen.findByText('Template not found')).toBeInTheDocument()
  })

  it('shows the permission state and no editing controls to a viewer', async () => {
    vi.mocked(api.me).mockResolvedValue({ role: 'viewer' } as never)
    renderAt('/settings/templates/tpl-1')
    expect(await screen.findByText('Administrator access required')).toBeInTheDocument()
    expect(screen.queryByRole('button', { name: 'Save new version' })).not.toBeInTheDocument()
    expect(screen.queryByRole('button', { name: /Activate/ })).not.toBeInTheDocument()
    expect(api.getNotificationTemplate).not.toHaveBeenCalled()
  })
})
