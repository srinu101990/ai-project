import { Biohazard, TriangleAlert } from 'lucide-react'
import {
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
  virus: '#f43f5e',
  worm: '#fb7185',
  trojan: '#ef4444',
  ransomware: '#a855f7',
  spyware: '#e879f9',
  adware: '#f472b6',
  rootkit: '#c084fc',
  botnet: '#818cf8',
  keylogger: '#38bdf8',
  rat: '#f97316',
  downloader: '#fb923c',
  backdoor: '#f87171',
  fileless: '#94a3b8',
  cryptominer: '#eab308',
  malware: '#ef4444',
  phishing: '#f97316',
  benign: '#22c55e',
  ddos: '#3b82f6',
  'brute-force': '#22d3ee',
  'brute force': '#22d3ee',
  social: '#4ade80',
}

const SEVERITY_ORDER = ['low', 'medium', 'high', 'critical']

const SEVERITY_COLORS = {
  critical: '#ef4444',
  high: '#f97316',
  medium: '#eab308',
  low: '#f87171',
}

function ChartTooltip({ active, payload, label }) {
  if (!active || !payload?.length) return null
  return (
    <div className="chart-tooltip">
      {label ? <div className="chart-tooltip-label">{label}</div> : null}
      {payload.map((item) => (
        <div key={item.name} style={{ color: item.color || '#e8f0ff' }}>
          {item.name}: <strong>{item.value}</strong>
        </div>
      ))}
    </div>
  )
}

function percentMap(entries) {
  const total = entries.reduce((sum, item) => sum + item.value, 0) || 1
  return entries.map((item) => ({
    ...item,
    pct: Math.round((item.value / total) * 1000) / 10,
  }))
}

export function ClassificationChart({ stats }) {
  const byType = percentMap(
    Object.entries(stats?.by_type || {}).map(([name, value]) => ({
      name,
      value,
    })),
  )

  return (
    <div className="panel section chart-panel">
      <div className="section-head">
        <h3>Threat Classification Distribution</h3>
        <span>Vector mix</span>
      </div>
      <div className="donut-layout">
        <div className="donut-chart">
          <ResponsiveContainer width="100%" height="100%">
            <PieChart>
              <Pie
                data={byType.length ? byType : [{ name: 'empty', value: 1 }]}
                dataKey="value"
                nameKey="name"
                innerRadius={58}
                outerRadius={88}
                paddingAngle={byType.length ? 3 : 0}
                stroke="rgba(5,10,24,0.85)"
                strokeWidth={3}
                animationDuration={900}
              >
                {(byType.length ? byType : [{ name: 'empty' }]).map((entry) => (
                  <Cell
                    key={entry.name}
                    fill={TYPE_COLORS[entry.name] || 'rgba(148,163,184,0.25)'}
                    style={{
                      filter: `drop-shadow(0 0 6px ${TYPE_COLORS[entry.name] || 'transparent'})`,
                    }}
                  />
                ))}
              </Pie>
              <Tooltip content={<ChartTooltip />} />
            </PieChart>
          </ResponsiveContainer>
          <div className="donut-center" aria-hidden="true">
            <Biohazard size={28} />
          </div>
        </div>
        <ul className="donut-legend">
          {byType.length === 0 ? (
            <li className="muted">No distribution data yet</li>
          ) : (
            byType.map((entry) => (
              <li key={entry.name}>
                <span
                  className="legend-swatch"
                  style={{ background: TYPE_COLORS[entry.name] || '#38bdf8' }}
                />
                <span className="legend-name">{entry.name}</span>
                <span className="legend-pct mono">{entry.pct}%</span>
              </li>
            ))
          )}
        </ul>
      </div>
    </div>
  )
}

export function SeverityChart({ stats }) {
  const severityLookup = stats?.by_severity || {}
  const bySeverity = SEVERITY_ORDER.map((name) => ({
    name: name.charAt(0).toUpperCase() + name.slice(1),
    key: name,
    value: severityLookup[name] || 0,
  }))

  return (
    <div className="panel section chart-panel severity-panel">
      <div className="section-head">
        <h3>Threat Severity Distribution</h3>
        <span>Risk bands</span>
      </div>
      <div className="chart-wrap severity-chart">
        <div className="severity-ghost" aria-hidden="true">
          <TriangleAlert size={120} strokeWidth={1} />
        </div>
        <ResponsiveContainer width="100%" height="100%">
          <BarChart data={bySeverity} barCategoryGap="28%">
            <CartesianGrid stroke="rgba(148,163,184,0.1)" vertical={false} />
            <XAxis
              dataKey="name"
              stroke="#7b8db0"
              fontSize={11}
              tickLine={false}
              axisLine={false}
            />
            <YAxis
              stroke="#7b8db0"
              fontSize={11}
              allowDecimals={false}
              tickLine={false}
              axisLine={false}
            />
            <Tooltip content={<ChartTooltip />} />
            <Bar dataKey="value" name="Incidents" radius={[8, 8, 0, 0]} animationDuration={900}>
              {bySeverity.map((entry) => (
                <Cell
                  key={entry.key}
                  fill={SEVERITY_COLORS[entry.key] || '#38bdf8'}
                  style={{
                    filter: `drop-shadow(0 0 8px ${SEVERITY_COLORS[entry.key] || 'transparent'})`,
                  }}
                />
              ))}
            </Bar>
          </BarChart>
        </ResponsiveContainer>
      </div>
    </div>
  )
}

/** Backward-compatible combined charts block. */
export default function ThreatCharts({ stats }) {
  return (
    <div className="viz-grid">
      <ClassificationChart stats={stats} />
      <SeverityChart stats={stats} />
    </div>
  )
}
