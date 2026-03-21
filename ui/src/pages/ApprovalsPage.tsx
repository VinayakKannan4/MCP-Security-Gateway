import { useEffect, useState } from 'react'
import { AuditEvent, fetchAuditEvents } from '../api/audit'
import { ApprovalRequest, fetchApproval } from '../api/approvals'
import { ApprovalCard } from '../components/ApprovalCard'

export function ApprovalsPage() {
  const [approvals, setApprovals] = useState<ApprovalRequest[]>([])
  const [loading, setLoading] = useState(true)
  const [error, setError] = useState<string | null>(null)

  const load = async () => {
    try {
      // Fetch recent audit events and filter for APPROVAL_REQUIRED ones to get tokens
      const events: AuditEvent[] = await fetchAuditEvents(100)
      const pending = events.filter((e) => e.decision === 'APPROVAL_REQUIRED')

      // Fetch approval details for each token (request_id doubles as token ref)
      const details = await Promise.allSettled(
        pending.map((e) => fetchApproval(e.request_id))
      )

      const resolved: ApprovalRequest[] = details
        .filter((r): r is PromiseFulfilledResult<ApprovalRequest> => r.status === 'fulfilled')
        .map((r) => r.value)

      setApprovals(resolved)
      setError(null)
    } catch (err) {
      setError(String(err))
    } finally {
      setLoading(false)
    }
  }

  useEffect(() => {
    void load()
  }, [])

  if (loading) {
    return <p style={{ color: '#94a3b8', padding: '24px' }}>Loading approvals…</p>
  }

  return (
    <div>
      <h2 style={{ margin: '0 0 20px', color: '#f1f5f9' }}>Approval Queue</h2>
      {error && (
        <p style={{ color: '#fca5a5', marginBottom: '12px' }}>Error: {error}</p>
      )}
      {approvals.length === 0 && !error && (
        <p style={{ color: '#64748b' }}>No pending approvals.</p>
      )}
      {approvals.map((a) => (
        <ApprovalCard key={a.token} approval={a} onActionComplete={() => void load()} />
      ))}
    </div>
  )
}
