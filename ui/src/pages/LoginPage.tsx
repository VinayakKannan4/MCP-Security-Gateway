import { FormEvent, useState } from 'react'
import { AdminIdentity, loginAdminSession } from '../api/auth'

interface LoginPageProps {
  onLogin: (identity: AdminIdentity) => void
}

const cardStyle: React.CSSProperties = {
  width: '100%',
  maxWidth: '420px',
  background: '#111827',
  border: '1px solid #1f2937',
  borderRadius: '16px',
  padding: '28px',
  boxShadow: '0 24px 60px rgba(15, 23, 42, 0.45)',
}

export function LoginPage({ onLogin }: LoginPageProps) {
  const [apiKey, setApiKey] = useState('')
  const [loading, setLoading] = useState(false)
  const [error, setError] = useState<string | null>(null)

  const handleSubmit = async (event: FormEvent<HTMLFormElement>) => {
    event.preventDefault()
    setLoading(true)
    setError(null)
    try {
      const identity = await loginAdminSession(apiKey)
      setApiKey('')
      onLogin(identity)
    } catch (err) {
      setError(String(err))
    } finally {
      setLoading(false)
    }
  }

  return (
    <div
      style={{
        minHeight: '100vh',
        display: 'grid',
        placeItems: 'center',
        padding: '24px',
        background:
          'radial-gradient(circle at top, rgba(14, 165, 233, 0.12), transparent 35%), #020617',
      }}
    >
      <div style={cardStyle}>
        <p style={{ margin: 0, color: '#38bdf8', fontSize: '0.8rem', letterSpacing: '0.12em' }}>
          ADMIN SESSION
        </p>
        <h1 style={{ margin: '12px 0 8px', color: '#f8fafc', fontSize: '1.8rem' }}>
          MCP Security Gateway
        </h1>
        <p style={{ margin: '0 0 24px', color: '#94a3b8', lineHeight: 1.5 }}>
          Enter an admin API key to create a short-lived bearer session for the dashboard.
        </p>
        <form onSubmit={handleSubmit}>
          <label
            htmlFor="api-key"
            style={{ display: 'block', marginBottom: '8px', color: '#cbd5e1', fontSize: '0.875rem' }}
          >
            Admin API Key
          </label>
          <input
            id="api-key"
            type="password"
            autoComplete="current-password"
            value={apiKey}
            onChange={(event) => setApiKey(event.target.value)}
            placeholder="Paste the admin key from seed_policies.py"
            style={{
              width: '100%',
              boxSizing: 'border-box',
              borderRadius: '10px',
              border: '1px solid #334155',
              background: '#0f172a',
              color: '#f8fafc',
              padding: '12px 14px',
              marginBottom: '14px',
            }}
          />
          <button
            type="submit"
            disabled={loading || apiKey.trim().length === 0}
            style={{
              width: '100%',
              border: 'none',
              borderRadius: '10px',
              padding: '12px 16px',
              background: loading ? '#334155' : '#0ea5e9',
              color: '#082f49',
              fontWeight: 700,
              cursor: loading ? 'wait' : 'pointer',
            }}
          >
            {loading ? 'Signing in...' : 'Create Admin Session'}
          </button>
        </form>
        {error && (
          <p style={{ margin: '14px 0 0', color: '#fca5a5', fontSize: '0.875rem' }}>
            {error}
          </p>
        )}
      </div>
    </div>
  )
}
