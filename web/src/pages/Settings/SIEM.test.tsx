import { render, screen } from '@testing-library/react'
import { beforeEach, describe, expect, it, vi } from 'vitest'
import { SIEM } from './SIEM'

vi.mock('../../lib/api', () => ({
  api: {
    me: vi.fn(),
    listSIEMSinks: vi.fn(),
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

describe('SIEM settings', () => {
  beforeEach(() => {
    vi.mocked(api.me).mockReset()
    vi.mocked(api.listSIEMSinks).mockReset()
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
  })

  it('shows a load error', async () => {
    vi.mocked(api.me).mockResolvedValue({ role: 'admin' } as never)
    vi.mocked(api.listSIEMSinks).mockRejectedValue(new Error('database unavailable'))
    render(<SIEM />)
    expect(await screen.findByText('database unavailable')).toBeInTheDocument()
  })
})
