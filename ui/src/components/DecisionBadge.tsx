interface DecisionBadgeProps {
  decision: string
}

const DECISION_STYLES: Record<string, { bg: string; text: string }> = {
  ALLOW: { bg: '#166534', text: '#86efac' },
  DENY: { bg: '#7f1d1d', text: '#fca5a5' },
  APPROVAL_REQUIRED: { bg: '#78350f', text: '#fcd34d' },
  SANITIZE_AND_ALLOW: { bg: '#1e3a5f', text: '#93c5fd' },
}

const DEFAULT_STYLE = { bg: '#1e293b', text: '#94a3b8' }

export function DecisionBadge({ decision }: DecisionBadgeProps) {
  const style = DECISION_STYLES[decision] ?? DEFAULT_STYLE
  return (
    <span
      style={{
        display: 'inline-block',
        padding: '2px 8px',
        borderRadius: '9999px',
        fontSize: '0.75rem',
        fontWeight: 600,
        backgroundColor: style.bg,
        color: style.text,
        whiteSpace: 'nowrap',
      }}
    >
      {decision}
    </span>
  )
}
