import { useEffect, useState } from 'react'
import { AuditEvent, fetchAuditEvents } from '../api/audit'
import { AuditTable } from '../components/AuditTable'

const REFRESH_INTERVAL_MS = 5000

export function AuditPage() {
  const [events, setEvents] = useState<AuditEvent[]>([])
  const [loading, setLoading] = useState(true)
  const [error, setError] = useState<string | null>(null)

  const load = async () => {
    try {
      const data = await fetchAuditEvents(50)
      setEvents(data)
      setError(null)
    } catch (err) {
      setError(String(err))
    } finally {
      setLoading(false)
    }
  }

  useEffect(() => {
    void load()
    const id = setInterval(() => void load(), REFRESH_INTERVAL_MS)
    return () => clearInterval(id)
  }, [])

  return (
    <div>
      <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: '16px' }}>
        <h2 style={{ margin: 0, color: '#f1f5f9' }}>Audit Log</h2>
        <span style={{ fontSize: '0.75rem', color: '#64748b' }}>Auto-refreshes every 5s</span>
      </div>
      {error && (
        <p style={{ color: '#fca5a5', marginBottom: '12px' }}>
          Failed to load audit events: {error}
        </p>
      )}
      <AuditTable events={events} loading={loading} />
    </div>
  )
}
