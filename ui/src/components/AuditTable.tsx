import { AuditEvent } from '../api/audit'
import { DecisionBadge } from './DecisionBadge'

interface AuditTableProps {
  events: AuditEvent[]
  loading: boolean
}

const cellStyle: React.CSSProperties = {
  padding: '10px 12px',
  borderBottom: '1px solid #1e293b',
  fontSize: '0.85rem',
  color: '#cbd5e1',
  maxWidth: '200px',
  overflow: 'hidden',
  textOverflow: 'ellipsis',
  whiteSpace: 'nowrap',
}

const headerStyle: React.CSSProperties = {
  ...cellStyle,
  color: '#94a3b8',
  fontWeight: 600,
  fontSize: '0.75rem',
  textTransform: 'uppercase',
  letterSpacing: '0.05em',
  background: '#0f172a',
}

export function AuditTable({ events, loading }: AuditTableProps) {
  if (loading && events.length === 0) {
    return <p style={{ color: '#94a3b8', padding: '24px' }}>Loading audit events…</p>
  }

  return (
    <div style={{ overflowX: 'auto' }}>
      <table style={{ width: '100%', borderCollapse: 'collapse' }}>
        <thead>
          <tr>
            <th style={headerStyle}>Timestamp</th>
            <th style={headerStyle}>Caller</th>
            <th style={headerStyle}>Tool</th>
            <th style={headerStyle}>Decision</th>
            <th style={headerStyle}>Matched Rule</th>
            <th style={headerStyle}>Latency (ms)</th>
          </tr>
        </thead>
        <tbody>
          {events.map((evt) => (
            <tr key={evt.request_id} style={{ background: '#0f172a' }}>
              <td style={cellStyle} title={evt.created_at}>
                {new Date(evt.created_at).toLocaleTimeString()}
              </td>
              <td style={cellStyle} title={evt.caller_id}>
                {evt.caller_id}
              </td>
              <td style={cellStyle} title={evt.tool_name}>
                {evt.tool_name}
              </td>
              <td style={{ ...cellStyle, maxWidth: 'none' }}>
                <DecisionBadge decision={evt.decision} />
              </td>
              <td style={cellStyle} title={evt.matched_policy_rule ?? ''}>
                {evt.matched_policy_rule ?? '—'}
              </td>
              <td style={{ ...cellStyle, fontVariantNumeric: 'tabular-nums' }}>
                {evt.latency_ms != null ? evt.latency_ms : '—'}
              </td>
            </tr>
          ))}
          {events.length === 0 && (
            <tr>
              <td colSpan={6} style={{ ...cellStyle, textAlign: 'center', color: '#475569' }}>
                No audit events found
              </td>
            </tr>
          )}
        </tbody>
      </table>
    </div>
  )
}
