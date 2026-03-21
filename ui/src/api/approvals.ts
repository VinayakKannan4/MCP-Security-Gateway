import { apiClient } from './client'

export interface ApprovalRequest {
  token: string
  caller_id: string
  tool_name: string
  status: 'pending' | 'approved' | 'denied' | 'expired'
  created_at: string
  expires_at: string | null
}

export async function fetchApproval(token: string): Promise<ApprovalRequest> {
  const response = await apiClient.get<ApprovalRequest>(`/v1/approvals/${token}`)
  return response.data
}

export async function approveRequest(token: string): Promise<void> {
  await apiClient.post(`/v1/approvals/${token}/approve`)
}

export async function denyRequest(token: string): Promise<void> {
  await apiClient.post(`/v1/approvals/${token}/deny`)
}
