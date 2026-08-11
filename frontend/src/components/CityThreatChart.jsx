import { Bar, BarChart, Cell, ResponsiveContainer, Tooltip, XAxis, YAxis } from 'recharts'
import { threatsByCity } from '../utils/cities'

function ChartTooltip({ active, payload, label }) {
  if (!active || !payload?.length) return null
  return (
    <div className="chart-tooltip">
      {label ? <div className="chart-tooltip-label">{label}</div> : null}
      {payload.map((item) => (
        <div key={item.name} style={{ color: item.color || '#e8f0ff' }}>
          Threats: <strong>{item.value}</strong>
        </div>
      ))}
    </div>
  )
}

export default function CityThreatChart({ threats }) {
  const data = threatsByCity(threats)

  return (
    <div className="panel section chart-panel city-panel">
      <div className="section-head">
        <h3>Threats by Indian City</h3>
        <span>Geo intel map</span>
      </div>
      <div className="chart-wrap city-chart">
        {data.length === 0 ? (
          <div className="empty">No city-mapped threats yet</div>
        ) : (
          <ResponsiveContainer width="100%" height="100%">
            <BarChart data={data} layout="vertical" margin={{ left: 12, right: 16, top: 8, bottom: 8 }}>
              <XAxis type="number" allowDecimals={false} stroke="#7b8db0" fontSize={11} tickLine={false} axisLine={false} />
              <YAxis
                type="category"
                dataKey="name"
                width={88}
                stroke="#7b8db0"
                fontSize={12}
                tickLine={false}
                axisLine={false}
              />
              <Tooltip content={<ChartTooltip />} />
              <Bar dataKey="value" name="Threats" radius={[0, 8, 8, 0]} barSize={16} animationDuration={900}>
                {data.map((entry) => (
                  <Cell key={entry.name} fill="#22d3ee" style={{ filter: 'drop-shadow(0 0 8px rgba(34,211,238,0.45))' }} />
                ))}
              </Bar>
            </BarChart>
          </ResponsiveContainer>
        )}
      </div>
    </div>
  )
}
