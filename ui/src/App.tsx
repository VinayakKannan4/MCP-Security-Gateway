import { useEffect, useState } from 'react'
import { BrowserRouter, Link, Route, Routes, useLocation } from 'react-router-dom'
import { AdminIdentity, logoutAdminSession, restoreAdminSession } from './api/auth'
import { AuditPage } from './pages/AuditPage'
import { ApprovalsPage } from './pages/ApprovalsPage'
import { LoginPage } from './pages/LoginPage'

const navStyle: React.CSSProperties = {
  display: 'flex',
  alignItems: 'center',
  gap: '24px',
  padding: '0 24px',
  height: '56px',
  background: '#0f172a',
  borderBottom: '1px solid #1e293b',
}

const brandStyle: React.CSSProperties = {
  fontWeight: 700,
  fontSize: '1rem',
  color: '#f1f5f9',
  textDecoration: 'none',
  marginRight: 'auto',
}

function NavLink({ to, label }: { to: string; label: string }) {
  const { pathname } = useLocation()
  const active = pathname === to
  return (
    <Link
      to={to}
      style={{
        color: active ? '#60a5fa' : '#94a3b8',
        textDecoration: 'none',
        fontSize: '0.875rem',
        fontWeight: active ? 600 : 400,
        borderBottom: active ? '2px solid #60a5fa' : '2px solid transparent',
        paddingBottom: '2px',
      }}
    >
      {label}
    </Link>
  )
}

function Layout({
  admin,
  onLogout,
}: {
  admin: AdminIdentity
  onLogout: () => Promise<void>
}) {
  return (
    <>
      <nav style={navStyle}>
        <span style={brandStyle}>MCP Security Gateway</span>
        <NavLink to="/" label="Audit Log" />
        <NavLink to="/approvals" label="Approvals" />
        <div style={{ display: 'flex', alignItems: 'center', gap: '12px' }}>
          <span style={{ color: '#94a3b8', fontSize: '0.8rem' }}>
            {admin.caller_id} · {admin.org_id}
          </span>
          <button
            onClick={() => void onLogout()}
            style={{
              border: '1px solid #334155',
              borderRadius: '999px',
              background: 'transparent',
              color: '#cbd5e1',
              padding: '6px 12px',
              cursor: 'pointer',
            }}
          >
            Sign out
          </button>
        </div>
      </nav>
      <main style={{ padding: '24px', maxWidth: '1200px', margin: '0 auto' }}>
        <Routes>
          <Route path="/" element={<AuditPage />} />
          <Route path="/approvals" element={<ApprovalsPage />} />
        </Routes>
      </main>
    </>
  )
}

export default function App() {
  const [admin, setAdmin] = useState<AdminIdentity | null>(null)
  const [loading, setLoading] = useState(true)

  useEffect(() => {
    void restoreAdminSession().then((identity) => {
      setAdmin(identity)
      setLoading(false)
    })
  }, [])

  const handleLogout = async () => {
    await logoutAdminSession()
    setAdmin(null)
  }

  if (loading) {
    return (
      <div
        style={{
          minHeight: '100vh',
          display: 'grid',
          placeItems: 'center',
          background: '#020617',
          color: '#94a3b8',
        }}
      >
        Restoring admin session...
      </div>
    )
  }

  if (!admin) {
    return <LoginPage onLogin={setAdmin} />
  }

  return (
    <BrowserRouter>
      <Layout admin={admin} onLogout={handleLogout} />
    </BrowserRouter>
  )
}
