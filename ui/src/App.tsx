import { BrowserRouter, Link, Route, Routes, useLocation } from 'react-router-dom'
import { AuditPage } from './pages/AuditPage'
import { ApprovalsPage } from './pages/ApprovalsPage'

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

function Layout() {
  return (
    <>
      <nav style={navStyle}>
        <span style={brandStyle}>MCP Security Gateway</span>
        <NavLink to="/" label="Audit Log" />
        <NavLink to="/approvals" label="Approvals" />
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
  return (
    <BrowserRouter>
      <Layout />
    </BrowserRouter>
  )
}
