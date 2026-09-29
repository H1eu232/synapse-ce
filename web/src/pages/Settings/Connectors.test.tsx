import { fireEvent, render, screen, waitFor } from '@testing-library/react'
import { beforeEach, describe, expect, it, vi } from 'vitest'
import { api } from '../../lib/api'
import { Connectors } from './Connectors'

vi.mock('../../lib/api', () => ({
  api: {
    listConnectors: vi.fn(),
    createConnector: vi.fn(),
    deleteConnector: vi.fn(),
  },
  ApiError: class ApiError extends Error {
    constructor(
      public status: number,
      message: string,
    ) {
      super(message)
    }
  },
}))

const CONNECTORS = [
  { id: 'conn-1', name: 'Production GitHub', provider: 'github', host: 'github.com', username: 'x-access-token', authKind: 'pat', createdAt: '', updatedAt: '' },
  { id: 'conn-2', name: 'Internal GitLab', provider: 'gitlab', host: 'gitlab.corp.internal', username: 'oauth2', authKind: 'pat', createdAt: '', updatedAt: '' },
]

describe('Connectors', () => {
  beforeEach(() => vi.resetAllMocks())

  it('lists connectors with provider and host, never a token', async () => {
    vi.mocked(api.listConnectors).mockResolvedValue(CONNECTORS as never)
    render(<Connectors />)
    expect(await screen.findByText('Production GitHub')).toBeInTheDocument()
    expect(screen.getByText('gitlab.corp.internal · oauth2')).toBeInTheDocument()
    // No token value is ever rendered.
    expect(screen.queryByText(/ghp_/)).not.toBeInTheDocument()
  })

  it('keeps the token field masked and creates a connector write-only', async () => {
    vi.mocked(api.listConnectors).mockResolvedValue([] as never)
    vi.mocked(api.createConnector).mockResolvedValue({ id: 'conn-new' } as never)
    render(<Connectors />)
    await screen.findByText('No connectors yet')

    const token = screen.getByLabelText(/Personal access token/) as HTMLInputElement
    expect(token.type).toBe('password') // masked by default
    fireEvent.click(screen.getByRole('button', { name: 'Show token' }))
    expect((screen.getByLabelText(/Personal access token/) as HTMLInputElement).type).toBe('text')

    fireEvent.change(screen.getByLabelText(/^Name/), { target: { value: 'Prod' } })
    fireEvent.change(screen.getByLabelText(/^Host/), { target: { value: 'github.com' } })
    fireEvent.change(screen.getByLabelText(/Personal access token/), { target: { value: 'ghp_secret' } })
    fireEvent.click(screen.getByRole('button', { name: /Add connector/ }))

    await waitFor(() => expect(api.createConnector).toHaveBeenCalledWith(
      expect.objectContaining({ name: 'Prod', provider: 'github', host: 'github.com', token: 'ghp_secret' }),
    ))
  })

  it('says so when connectors are not enabled on the deployment', async () => {
    vi.mocked(api.listConnectors).mockResolvedValue(null as never)
    render(<Connectors />)
    expect(await screen.findByText('Connectors are not enabled on this deployment')).toBeInTheDocument()
  })
  it('displays Azure DevOps connector metadata without exposing the PAT', async () => {
    vi.mocked(api.listConnectors).mockResolvedValue([{
      id: 'azure-conn', name: 'Azure project', provider: 'azure-devops',
      host: 'dev.azure.com', username: 'pat', authKind: 'pat',
      createdAt: '', updatedAt: '',
    }] as never)
    render(<Connectors />)
    expect(await screen.findByText('Azure project')).toBeInTheDocument()
    expect(screen.getAllByText('Azure DevOps').length).toBeGreaterThanOrEqual(2)
    expect(screen.getByText('dev.azure.com · pat')).toBeInTheDocument()
    expect(screen.queryByText('secret-azure-pat')).not.toBeInTheDocument()
  })

  it('creates an Azure DevOps connector with the provider-specific defaults', async () => {
    vi.mocked(api.listConnectors).mockResolvedValue([] as never)
    vi.mocked(api.createConnector).mockResolvedValue({ id: 'azure-new' } as never)
    render(<Connectors />)
    await screen.findByText('No connectors yet')

    const nativeProvider = document.querySelector('select') as HTMLSelectElement | null
    expect(nativeProvider).not.toBeNull()
    fireEvent.change(nativeProvider!, { target: { value: 'azure-devops' } })
    expect(screen.getByPlaceholderText('dev.azure.com')).toBeInTheDocument()
    expect(screen.getByPlaceholderText('pat')).toBeInTheDocument()
    expect(screen.getByPlaceholderText('Azure DevOps PAT')).toHaveAttribute('type', 'password')
    expect(screen.getByText(/Code \(Read & write\).*Code \(Status\)/)).toBeInTheDocument()

    fireEvent.change(screen.getByLabelText(/^Name/), { target: { value: 'Azure project' } })
    fireEvent.change(screen.getByLabelText(/^Host/), { target: { value: 'dev.azure.com' } })
    fireEvent.change(screen.getByLabelText(/Personal access token/), { target: { value: 'azure-secret-pat' } })
    fireEvent.click(screen.getByRole('button', { name: /Add connector/ }))

    await waitFor(() => expect(api.createConnector).toHaveBeenCalledWith(expect.objectContaining({
      name: 'Azure project',
      provider: 'azure-devops',
      host: 'dev.azure.com',
      token: 'azure-secret-pat',
    })))
  })

})
