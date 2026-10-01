import { ApiError, errorFromResponse } from './errors'

export { ApiError } from './errors'

let token = ''
let csrfToken = ''
// Called when a response says the caller is no longer authenticated. It receives the parsed error so
// it can tell a rejected credential from a missing one; streaming callers that only see a bare 401
// invoke it without an argument.
type UnauthorizedHandler = (error?: ApiError) => void
let onUnauthorized: UnauthorizedHandler | null = null

export function setToken(t: string): void {
  token = t
}

// The BFF issues this token with the session; it intentionally remains in memory only.
export function setCSRFToken(t: string): void {
  csrfToken = t
}

export function setUnauthorizedHandler(fn: UnauthorizedHandler): void {
  onUnauthorized = fn
}

export function getToken(): string {
  return token
}

export function getOnUnauthorized(): UnauthorizedHandler | null {
  return onUnauthorized
}

export function newIdempotencyKey(): string {
  if (globalThis.crypto?.randomUUID) return globalThis.crypto.randomUUID()
  const bytes = new Uint8Array(16)
  globalThis.crypto.getRandomValues(bytes)
  return Array.from(bytes, (value) => value.toString(16).padStart(2, '0')).join('')
}

export type BFFSession = { authenticated: boolean; csrfToken: string }

function apiRequestInit(init: RequestInit = {}, json = true): RequestInit {
  const method = (init.method ?? 'GET').toUpperCase()
  const headers: Record<string, string> = {}
  const formData = typeof FormData !== 'undefined' && init.body instanceof FormData
  if (json && !formData) headers['content-type'] = 'application/json'
  if (token) headers.authorization = `Bearer ${token}`
  else if (!['GET', 'HEAD', 'OPTIONS', 'TRACE'].includes(method) && csrfToken) headers['X-CSRF-Token'] = csrfToken
  return { ...init, credentials: token ? 'omit' : 'same-origin', headers: { ...headers, ...(init.headers as Record<string, string> ?? {}) } }
}

// Only an authentication outcome reaches the global handler. A 503 authentication_unavailable, a
// 403 of any kind or another 5xx describes a dependency or an authorization decision, not the
// credential, so it never signs the operator out.
function notifyUnauthorized(error: ApiError): void {
  if (!onUnauthorized) return
  if (error.status === 401 || error.code === 'authentication_invalid') onUnauthorized(error)
}

// Discovery rotates the session. When two tabs discover at the same moment one rotation wins and the
// other gets 409 conflict with the cookie left in place; the browser already holds the winner's
// replacement cookie, so one more attempt picks it up.
const DISCOVERY_CONFLICT_RETRY_MS = 250

async function fetchSession(): Promise<Response> {
  try {
    return await fetch('/api/auth/session', { credentials: 'same-origin' })
  } catch {
    throw new ApiError(0, 'Cannot reach the API. Is the server running on :8080?')
  }
}

export async function discoverSession(): Promise<BFFSession> {
  let res = await fetchSession()
  if (res.status === 409) {
    await new Promise((resolve) => setTimeout(resolve, DISCOVERY_CONFLICT_RETRY_MS))
    res = await fetchSession()
  }
  // 401/403 = not signed in; 404 = a token-only server that doesn't mount the OIDC BFF
  // (the /api/auth/* routes are registered only when OIDC is enabled). Both mean "no
  // session" — surface the login screen rather than an error. A 503 authentication_unavailable
  // or any other failure is thrown instead: the session store could not answer, which says
  // nothing about whether the cookie is still valid.
  if (res.status === 401 || res.status === 403 || res.status === 404) return { authenticated: false, csrfToken: '' }
  if (!res.ok) throw await errorFromResponse(res)
  const body = await res.json()
  if (body?.authenticated !== true) return { authenticated: false, csrfToken: '' }
  const csrf = body?.csrf_token ?? body?.csrfToken ?? body?.csrf
  if (typeof csrf !== 'string' || csrf === '') {
    throw new ApiError(res.status, 'The sign-in session did not include a CSRF token.')
  }
  return { authenticated: true, csrfToken: csrf }
}

export async function logoutSession(): Promise<void> {
  let res: Response
  try {
    res = await fetch('/api/auth/logout', apiRequestInit({ method: 'POST' }))
  } catch {
    throw new ApiError(0, 'Cannot reach the API. Is the server running on :8080?')
  }
  if (!res.ok) throw await errorFromResponse(res)
}

export async function req(path: string, init?: RequestInit): Promise<any> {
  let res: Response
  try {
    res = await fetch(`/api/v1${path}`, apiRequestInit(init))
  } catch (error) {
    if (error instanceof DOMException && error.name === 'AbortError') {
      throw error
    }
    throw new ApiError(0, 'Cannot reach the API. Is the server running on :8080?')
  }
  if (!res.ok) {
    const error = await errorFromResponse(res)
    notifyUnauthorized(error)
    throw error
  }
  if (res.status === 204) return null
  return res.json()
}

/** Fetch a SARIF/OpenVEX export with the bearer token and trigger a browser download. */
export async function blobDownload(path: string, fallbackName: string): Promise<void> {
  const res = await fetch(path, apiRequestInit({}, false))
  if (!res.ok) {
    const error = await errorFromResponse(res)
    notifyUnauthorized(error)
    throw error
  }
  const blob = await res.blob()
  const cd = res.headers.get('content-disposition') ?? ''
  const filename = /filename="([^"]+)"/.exec(cd)?.[1] ?? fallbackName
  const url = URL.createObjectURL(blob)
  const a = document.createElement('a')
  a.href = url
  a.download = filename
  document.body.appendChild(a)
  a.click()
  a.remove()
  URL.revokeObjectURL(url)
}
