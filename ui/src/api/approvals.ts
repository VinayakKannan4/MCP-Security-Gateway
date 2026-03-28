import { apiClient } from './client'

export interface ApprovalSummary {
  token: string
  caller_id: string
  org_id: string
  tool_name: string
  server: string
  status: 'PENDING' | 'APPROVED' | 'DENIED' | 'EXPIRED' | 'USED'
  scope: 'EXECUTION' | 'OUTPUT_RELEASE'
  created_at: string
  expires_at: string
  approver_id: string | null
  decided_at: string | null
}

export async function fetchPendingApprovals(): Promise<ApprovalSummary[]> {
  const response = await apiClient.get<ApprovalSummary[]>('/v1/approvals/', {
    params: { status: 'PENDING' },
  })
  return response.data
}

export async function approveRequest(token: string, note = 'Approved via dashboard'): Promise<void> {
  await apiClient.post(`/v1/approvals/${token}/approve`, null, {
    params: { note },
  })
}

export async function denyRequest(token: string, note = 'Denied via dashboard'): Promise<void> {
  await apiClient.post(`/v1/approvals/${token}/deny`, null, {
    params: { note },
  })
}
