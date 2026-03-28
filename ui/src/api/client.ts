import axios, { AxiosHeaders } from 'axios'

const baseURL = import.meta.env.VITE_API_BASE_URL ?? ''
const ADMIN_SESSION_STORAGE_KEY = 'mcp-security-gateway.admin-session'

export function getAdminSessionToken(): string | null {
  if (typeof window === 'undefined') {
    return null
  }
  return window.localStorage.getItem(ADMIN_SESSION_STORAGE_KEY)
}

export function setAdminSessionToken(token: string | null): void {
  if (typeof window === 'undefined') {
    return
  }
  if (token) {
    window.localStorage.setItem(ADMIN_SESSION_STORAGE_KEY, token)
    return
  }
  window.localStorage.removeItem(ADMIN_SESSION_STORAGE_KEY)
}

export const apiClient = axios.create({
  baseURL,
  headers: {
    'Content-Type': 'application/json',
  },
})

apiClient.interceptors.request.use((config) => {
  const token = getAdminSessionToken()
  const headers = AxiosHeaders.from(config.headers ?? {})
  if (token) {
    headers.set('Authorization', `Bearer ${token}`)
  } else {
    headers.delete('Authorization')
  }
  config.headers = headers
  return config
})
