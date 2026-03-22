import { useEffect, useState } from 'react'
import { ApprovalSummary, fetchPendingApprovals } from '../api/approvals'
import { ApprovalCard } from '../components/ApprovalCard'

export function ApprovalsPage() {
  const [approvals, setApprovals] = useState<ApprovalSummary[]>([])
  const [loading, setLoading] = useState(true)
  const [error, setError] = useState<string | null>(null)

  const load = async () => {
    try {
      const data = await fetchPendingApprovals()
      setApprovals(data)
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
