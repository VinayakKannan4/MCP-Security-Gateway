import { apiClient } from './client'

export interface ApprovalSummary {
  token: string
  caller_id: string
  tool_name: string
  server: string
  status: 'PENDING' | 'APPROVED' | 'DENIED' | 'EXPIRED'
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

export async function approveRequest(token: string): Promise<void> {
  await apiClient.post(`/v1/approvals/${token}/approve`, null, {
    params: { approver_id: 'dashboard-admin', note: 'Approved via dashboard' },
  })
}

export async function denyRequest(token: string): Promise<void> {
  await apiClient.post(`/v1/approvals/${token}/deny`, null, {
    params: { approver_id: 'dashboard-admin', note: 'Denied via dashboard' },
  })
}
