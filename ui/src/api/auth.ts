import { apiClient, getAdminSessionToken, setAdminSessionToken } from './client'

export interface AdminSessionResponse {
  session_token: string
  caller_id: string
  role: string
  environment: string
  api_key_id: number
  org_id: string
  expires_at: string
}

export interface AdminIdentity {
  caller_id: string
  role: string
  trust_level: number
  environment: string
  api_key_id: number
  org_id: string
}

export async function loginAdminSession(apiKey: string): Promise<AdminIdentity> {
  const response = await apiClient.post<AdminSessionResponse>('/v1/admin/login', {
    api_key: apiKey,
  })
  setAdminSessionToken(response.data.session_token)
  return fetchAdminIdentity()
}

export async function fetchAdminIdentity(): Promise<AdminIdentity> {
  const response = await apiClient.get<AdminIdentity>('/v1/admin/me')
  return response.data
}

export async function restoreAdminSession(): Promise<AdminIdentity | null> {
  if (!getAdminSessionToken()) {
    return null
  }
  try {
    return await fetchAdminIdentity()
  } catch {
    setAdminSessionToken(null)
    return null
  }
}

export async function logoutAdminSession(): Promise<void> {
  try {
    if (getAdminSessionToken()) {
      await apiClient.post('/v1/admin/logout')
    }
  } finally {
    setAdminSessionToken(null)
  }
}
