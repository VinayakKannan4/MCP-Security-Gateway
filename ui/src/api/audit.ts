import { apiClient } from './client'

export interface AuditEvent {
  request_id: string
  caller_id: string
  tool_name: string
  decision: string
  matched_policy_rule: string | null
  latency_ms: number | null
  created_at: string
}

export async function fetchAuditEvents(limit = 50): Promise<AuditEvent[]> {
  const response = await apiClient.get<AuditEvent[]>('/v1/audit/', {
    params: { limit },
  })
  return response.data
}
