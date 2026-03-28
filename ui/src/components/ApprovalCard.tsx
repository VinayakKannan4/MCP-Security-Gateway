import { useState } from 'react'
import { ApprovalSummary, approveRequest, denyRequest } from '../api/approvals'

interface ApprovalCardProps {
  approval: ApprovalSummary
  onActionComplete: () => void
}

const btnBase: React.CSSProperties = {
  padding: '8px 20px',
  borderRadius: '6px',
  border: 'none',
  cursor: 'pointer',
  fontWeight: 600,
  fontSize: '0.875rem',
  transition: 'opacity 0.15s',
}

export function ApprovalCard({ approval, onActionComplete }: ApprovalCardProps) {
  const [busy, setBusy] = useState(false)
  const [error, setError] = useState<string | null>(null)

  const handle = async (action: 'approve' | 'deny') => {
    setBusy(true)
    setError(null)
    try {
      if (action === 'approve') {
        await approveRequest(approval.token)
      } else {
        await denyRequest(approval.token)
      }
      onActionComplete()
    } catch (err) {
      setError(String(err))
    } finally {
      setBusy(false)
    }
  }

  return (
    <div
      style={{
        background: '#1e293b',
        border: '1px solid #334155',
        borderRadius: '8px',
        padding: '20px',
        marginBottom: '16px',
      }}
    >
      <div style={{ marginBottom: '12px' }}>
        <span style={{ color: '#94a3b8', fontSize: '0.75rem' }}>TOOL</span>
        <p style={{ margin: '2px 0', fontWeight: 600, fontSize: '1rem', color: '#f1f5f9' }}>
          {approval.tool_name}
        </p>
      </div>
      <div style={{ marginBottom: '12px' }}>
        <span style={{ color: '#94a3b8', fontSize: '0.75rem' }}>SERVER</span>
        <p style={{ margin: '2px 0', fontSize: '0.875rem', color: '#cbd5e1' }}>
          {approval.server}
        </p>
      </div>
      <div style={{ marginBottom: '12px' }}>
        <span style={{ color: '#94a3b8', fontSize: '0.75rem' }}>CALLER</span>
        <p style={{ margin: '2px 0', fontSize: '0.875rem', color: '#cbd5e1' }}>
          {approval.caller_id} · {approval.org_id}
        </p>
      </div>
      <div style={{ marginBottom: '12px' }}>
        <span style={{ color: '#94a3b8', fontSize: '0.75rem' }}>SCOPE</span>
        <p style={{ margin: '2px 0', fontSize: '0.875rem', color: '#fcd34d' }}>
          {approval.scope}
        </p>
      </div>
      <div style={{ marginBottom: '12px' }}>
        <span style={{ color: '#94a3b8', fontSize: '0.75rem' }}>STATUS</span>
        <p style={{ margin: '2px 0', fontSize: '0.875rem', color: '#fcd34d' }}>
          {approval.status}
        </p>
      </div>
      <div style={{ marginBottom: '16px' }}>
        <span style={{ color: '#94a3b8', fontSize: '0.75rem' }}>REQUESTED</span>
        <p style={{ margin: '2px 0', fontSize: '0.875rem', color: '#cbd5e1' }}>
          {new Date(approval.created_at).toLocaleString()}
        </p>
      </div>

      {approval.status === 'PENDING' && (
        <div style={{ display: 'flex', gap: '10px' }}>
          <button
            style={{ ...btnBase, background: '#166534', color: '#86efac', opacity: busy ? 0.6 : 1 }}
            disabled={busy}
            onClick={() => handle('approve')}
          >
            Approve
          </button>
          <button
            style={{ ...btnBase, background: '#7f1d1d', color: '#fca5a5', opacity: busy ? 0.6 : 1 }}
            disabled={busy}
            onClick={() => handle('deny')}
          >
            Deny
          </button>
        </div>
      )}

      {error && (
        <p style={{ color: '#fca5a5', fontSize: '0.8rem', marginTop: '8px' }}>Error: {error}</p>
      )}
    </div>
  )
}
