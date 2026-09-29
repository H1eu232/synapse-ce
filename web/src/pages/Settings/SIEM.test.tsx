import { fireEvent, render, screen, waitFor } from '@testing-library/react'
import { beforeEach, describe, expect, it, vi } from 'vitest'
import type { SIEMSink } from '../../lib/api'
import { SIEM } from './SIEM'

vi.mock('../../lib/api', () => ({
  api: {
    me: vi.fn(),
    listSIEMSinks: vi.fn(),
    pauseSIEMSink: vi.fn(),
    resumeSIEMSink: vi.fn(),
  },
  ApiError: class ApiError extends Error {
    status: number
    constructor(status: number, message: string) {
      super(message)
      this.status = status
    }
  },
}))

import { api } from '../../lib/api'

const blockedSink: SIEMSink = {
  id: 'sink-blocked',
  tenant_id: 'tenant-a',
  name: 'Blocked collector',
  provider: 'splunk_hec',
  origin: 'https://splunk.example:8088',
  target: '/services/collector/event',
  data_class: 'signal',
  ack_mode: 'hec_acceptance',
  indexer_ack_supported: false,
  paused: false,
  enabled: true,
  generation: 1,
  secret_version: 1,
  version: 4,
  channel: 'channel',
  blocked_reason: 'provider rejected a record',
  created_at: '2026-09-27T00:00:00Z',
  updated_at: '2026-09-27T00:00:00Z',
}

describe('SIEM settings', () => {
  beforeEach(() => {
    vi.mocked(api.me).mockReset()
    vi.mocked(api.listSIEMSinks).mockReset()
    vi.mocked(api.pauseSIEMSink).mockReset()
    vi.mocked(api.resumeSIEMSink).mockReset()
  })

  it('shows a permission state for a reader', async () => {
    vi.mocked(api.me).mockResolvedValue({ role: 'readonly' } as never)
    render(<SIEM />)
    expect(await screen.findByText('Administrator access required')).toBeInTheDocument()
  })

  it('shows an empty stream list', async () => {
    vi.mocked(api.me).mockResolvedValue({ role: 'admin' } as never)
    vi.mocked(api.listSIEMSinks).mockResolvedValue([])
    render(<SIEM />)
    expect(await screen.findByText('No SIEM destinations')).toBeInTheDocument()
    expect(screen.getByLabelText('Name')).toBeInTheDocument()
    expect(screen.getByText(/not currently available/i)).toBeInTheDocument()
    expect(screen.queryByLabelText('Data class')).not.toBeInTheDocument()
  })

  it('resumes a blocked sink that is not paused', async () => {
    vi.mocked(api.me).mockResolvedValue({ role: 'admin' } as never)
    vi.mocked(api.listSIEMSinks).mockResolvedValue([blockedSink])
    vi.mocked(api.resumeSIEMSink).mockResolvedValue({ ...blockedSink, blocked_reason: undefined, version: 5 })
    render(<SIEM />)
    expect(await screen.findByText('provider rejected a record')).toBeInTheDocument()
    expect(screen.getByRole('button', { name: 'Pause' })).toBeInTheDocument()
    fireEvent.click(screen.getByRole('button', { name: 'Resume' }))
    await waitFor(() => {
      expect(api.resumeSIEMSink).toHaveBeenCalledWith('sink-blocked', 4)
    })
  })

  // #1358: an integration_admin runs existing sinks; adding one stays with administrators.
  it('lets an integration_admin pause and resume a sink but not add one', async () => {
    vi.mocked(api.me).mockResolvedValue({ role: 'integration_admin' } as never)
    vi.mocked(api.listSIEMSinks).mockResolvedValue([blockedSink])
    vi.mocked(api.resumeSIEMSink).mockResolvedValue({ ...blockedSink, blocked_reason: undefined, version: 5 })
    render(<SIEM />)
    expect(await screen.findByText('Blocked collector')).toBeInTheDocument()
    expect(screen.getByText(/Only tenant administrators can add a sink/)).toBeInTheDocument()
    expect(screen.queryByRole('button', { name: 'Add sink' })).not.toBeInTheDocument()
    fireEvent.click(screen.getByRole('button', { name: 'Resume' }))
    await waitFor(() => expect(api.resumeSIEMSink).toHaveBeenCalledWith('sink-blocked', 4))
  })

  it('shows a load error', async () => {
    vi.mocked(api.me).mockResolvedValue({ role: 'admin' } as never)
    vi.mocked(api.listSIEMSinks).mockRejectedValue(new Error('database unavailable'))
    render(<SIEM />)
    expect(await screen.findByText('database unavailable')).toBeInTheDocument()
  })
})
