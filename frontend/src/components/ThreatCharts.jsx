import {
  Area,
  AreaChart,
  Bar,
  BarChart,
  CartesianGrid,
  Cell,
  Pie,
  PieChart,
  ResponsiveContainer,
  Tooltip,
  XAxis,
  YAxis,
} from 'recharts'

const TYPE_COLORS = {
  phishing: '#f59e0b',
  malware: '#f43f5e',
  ransomware: '#fb7185',
  benign: '#34d399',
}

const SEVERITY_COLORS = {
  critical: '#f43f5e',
  high: '#f59e0b',
  medium: '#38bdf8',
  low: '#34d399',
}

function ChartTooltip({ active, payload, label }) {
  if (!active || !payload?.length) return null
  return (
    <div
      style={{
        background: '#0c232a',
        border: '1px solid rgba(45,212,191,0.25)',
        borderRadius: 10,
        padding: '0.55rem 0.7rem',
        fontSize: 12,
      }}
    >
      {label ? <div style={{ marginBottom: 4, color: '#8aa8a8' }}>{label}</div> : null}
      {payload.map((item) => (
        <div key={item.name} style={{ color: item.color || '#e8f4f2' }}>
          {item.name}: <strong>{item.value}</strong>
        </div>
      ))}
    </div>
  )
}

export default function ThreatCharts({ stats }) {
  const byType = Object.entries(stats?.by_type || {}).map(([name, value]) => ({
    name,
    value,
  }))
  const bySeverity = Object.entries(stats?.by_severity || {}).map(([name, value]) => ({
    name,
    value,
  }))
  const timeline = stats?.timeline || []

  return (
    <div className="chart-pair">
      <div className="panel section">
        <div className="section-head">
          <h3>Threat Timeline</h3>
          <span>Real-time intake</span>
        </div>
        <div className="chart-wrap">
          <ResponsiveContainer width="100%" height="100%">
            <AreaChart data={timeline}>
              <defs>
                <linearGradient id="tealFill" x1="0" y1="0" x2="0" y2="1">
                  <stop offset="0%" stopColor="#2dd4bf" stopOpacity={0.45} />
                  <stop offset="100%" stopColor="#2dd4bf" stopOpacity={0.02} />
                </linearGradient>
              </defs>
              <CartesianGrid stroke="rgba(148,163,184,0.12)" vertical={false} />
              <XAxis dataKey="time" stroke="#8aa8a8" fontSize={11} tickLine={false} />
              <YAxis stroke="#8aa8a8" fontSize={11} allowDecimals={false} tickLine={false} />
              <Tooltip content={<ChartTooltip />} />
              <Area
                type="monotone"
                dataKey="count"
                name="Events"
                stroke="#2dd4bf"
                fill="url(#tealFill)"
                strokeWidth={2.2}
                animationDuration={900}
              />
            </AreaChart>
          </ResponsiveContainer>
        </div>
      </div>

      <div className="panel section">
        <div className="section-head">
          <h3>Classification Mix</h3>
          <span>AI threat types</span>
        </div>
        <div className="chart-wrap" style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: 8 }}>
          <ResponsiveContainer width="100%" height="100%">
            <PieChart>
              <Pie
                data={byType}
                dataKey="value"
                nameKey="name"
                innerRadius={48}
                outerRadius={78}
                paddingAngle={3}
                animationDuration={900}
              >
                {byType.map((entry) => (
                  <Cell key={entry.name} fill={TYPE_COLORS[entry.name] || '#38bdf8'} />
                ))}
              </Pie>
              <Tooltip content={<ChartTooltip />} />
            </PieChart>
          </ResponsiveContainer>
          <ResponsiveContainer width="100%" height="100%">
            <BarChart data={bySeverity}>
              <CartesianGrid stroke="rgba(148,163,184,0.12)" vertical={false} />
              <XAxis dataKey="name" stroke="#8aa8a8" fontSize={11} tickLine={false} />
              <YAxis stroke="#8aa8a8" fontSize={11} allowDecimals={false} tickLine={false} />
              <Tooltip content={<ChartTooltip />} />
              <Bar dataKey="value" name="Count" radius={[6, 6, 0, 0]} animationDuration={900}>
                {bySeverity.map((entry) => (
                  <Cell key={entry.name} fill={SEVERITY_COLORS[entry.name] || '#38bdf8'} />
                ))}
              </Bar>
            </BarChart>
          </ResponsiveContainer>
        </div>
      </div>
    </div>
  )
}
