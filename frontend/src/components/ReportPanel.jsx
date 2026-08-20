import { useEffect, useMemo, useState } from 'react'
import { createPortal } from 'react-dom'
import { FileDown, RotateCcw, ShieldAlert, X } from 'lucide-react'
import { api } from '../api'

const SEVERITIES = ['critical', 'high', 'medium', 'low']

function blankFilters() {
  return {
    dateMode: 'all',
    date: '',
    dateFrom: '',
    dateTo: '',
    severities: [],
    threatTypes: [],
    sources: [],
    sourceIps: [],
  }
}

function uniqueSorted(values) {
  return [...new Set((values || []).filter(Boolean))].sort((left, right) =>
    String(left).localeCompare(String(right)),
  )
}

function formatWhen(value) {
  if (!value) return '—'
  try {
    return new Date(value).toLocaleString('en-GB', {
      day: '2-digit',
      month: 'short',
      year: 'numeric',
      hour: '2-digit',
      minute: '2-digit',
    })
  } catch {
    return String(value)
  }
}

function toQuery(filters) {
  const params = {}
  if (filters.dateMode === 'date' && filters.date) params.date = filters.date
  if (filters.dateMode === 'range') {
    if (filters.dateFrom) params.date_from = filters.dateFrom
    if (filters.dateTo) params.date_to = filters.dateTo
  }
  if (filters.severities.length) params.severity = filters.severities
  if (filters.threatTypes.length) params.threat_type = filters.threatTypes
  if (filters.sources.length) params.source = filters.sources
  if (filters.sourceIps.length) params.source_ip = filters.sourceIps
  return params
}

function ChipGroup({ label, values, selected, onToggle, onSelectAll, onClear }) {
  return (
    <fieldset className="report-filter-group">
      <legend>
        {label}
        <span className="report-filter-legend-actions">
          <button type="button" className="text-btn" onClick={onSelectAll}>
            Select all
          </button>
          <button type="button" className="text-btn" onClick={onClear}>
            Clear
          </button>
        </span>
      </legend>
      <div className="report-chip-grid">
        {values.length ? (
          values.map((value) => {
            const checked = selected.includes(value)
            return (
              <label key={value} className={`report-chip ${checked ? 'on' : ''}`}>
                <input
                  type="checkbox"
                  checked={checked}
                  onChange={() => onToggle(value)}
                />
                {value}
              </label>
            )
          })
        ) : (
          <span className="muted">No values yet</span>
        )}
      </div>
    </fieldset>
  )
}

function ExportModal({
  open,
  onClose,
  onGenerate,
  downloading,
  options,
  filters,
  setFilters,
  preview,
}) {
  useEffect(() => {
    if (!open) return undefined
    function onKeyDown(event) {
      if (event.key === 'Escape') onClose()
    }
    document.addEventListener('keydown', onKeyDown)
    return () => document.removeEventListener('keydown', onKeyDown)
  }, [open, onClose])

  if (!open || typeof document === 'undefined') return null

  function toggle(listName, value) {
    setFilters((prev) => {
      const current = prev[listName]
      const next = current.includes(value)
        ? current.filter((item) => item !== value)
        : [...current, value]
      return { ...prev, [listName]: next }
    })
  }

  const applied = preview?.filter_label || 'Total / All Reports'
  const matchCount = preview?.match_count ?? preview?.total_threats
  const empty = Number(matchCount) === 0
  const dateIncomplete =
    (filters.dateMode === 'date' && !filters.date) ||
    (filters.dateMode === 'range' && !filters.dateFrom && !filters.dateTo)

  return createPortal(
    <div className="threat-popup-overlay" role="presentation" onClick={onClose}>
      <div
        className="threat-popup-modal report-export-modal"
        role="dialog"
        aria-modal="true"
        aria-labelledby="report-export-title"
        onClick={(event) => event.stopPropagation()}
      >
        <button type="button" className="threat-popup-close" aria-label="Close" onClick={onClose}>
          <X size={18} />
        </button>
        <h3 id="report-export-title" className="threat-popup-heading">
          Download PDF
        </h3>
        <p className="muted report-export-lead">
          Choose which report data to include. Filters combine together (AND).
        </p>

        <fieldset className="report-filter-group">
          <legend>Date</legend>
          <div className="report-date-modes">
            {[
              ['all', 'Total / All Reports'],
              ['date', 'Date-wise'],
              ['range', 'Custom Date Range'],
            ].map(([mode, label]) => (
              <label key={mode} className={`report-chip ${filters.dateMode === mode ? 'on' : ''}`}>
                <input
                  type="radio"
                  name="report-date-mode"
                  checked={filters.dateMode === mode}
                  onChange={() => setFilters((prev) => ({ ...prev, dateMode: mode }))}
                />
                {label}
              </label>
            ))}
          </div>
          {filters.dateMode === 'date' ? (
            <label className="report-date-field">
              Select date
              <input
                type="date"
                value={filters.date}
                onChange={(event) => setFilters((prev) => ({ ...prev, date: event.target.value }))}
              />
            </label>
          ) : null}
          {filters.dateMode === 'range' ? (
            <div className="report-date-range">
              <label className="report-date-field">
                From date
                <input
                  type="date"
                  value={filters.dateFrom}
                  onChange={(event) =>
                    setFilters((prev) => ({ ...prev, dateFrom: event.target.value }))
                  }
                />
              </label>
              <label className="report-date-field">
                To date
                <input
                  type="date"
                  value={filters.dateTo}
                  onChange={(event) =>
                    setFilters((prev) => ({ ...prev, dateTo: event.target.value }))
                  }
                />
              </label>
            </div>
          ) : null}
        </fieldset>

        <ChipGroup
          label="Severity"
          values={SEVERITIES}
          selected={filters.severities}
          onToggle={(value) => toggle('severities', value)}
          onSelectAll={() => setFilters((prev) => ({ ...prev, severities: [...SEVERITIES] }))}
          onClear={() => setFilters((prev) => ({ ...prev, severities: [] }))}
        />
        <ChipGroup
          label="Threat type"
          values={options.threatTypes}
          selected={filters.threatTypes}
          onToggle={(value) => toggle('threatTypes', value)}
          onSelectAll={() =>
            setFilters((prev) => ({ ...prev, threatTypes: [...options.threatTypes] }))
          }
          onClear={() => setFilters((prev) => ({ ...prev, threatTypes: [] }))}
        />
        <ChipGroup
          label="Affected system / device"
          values={options.sourceIps}
          selected={filters.sourceIps}
          onToggle={(value) => toggle('sourceIps', value)}
          onSelectAll={() =>
            setFilters((prev) => ({ ...prev, sourceIps: [...options.sourceIps] }))
          }
          onClear={() => setFilters((prev) => ({ ...prev, sourceIps: [] }))}
        />
        <ChipGroup
          label="Source"
          values={options.sources}
          selected={filters.sources}
          onToggle={(value) => toggle('sources', value)}
          onSelectAll={() => setFilters((prev) => ({ ...prev, sources: [...options.sources] }))}
          onClear={() => setFilters((prev) => ({ ...prev, sources: [] }))}
        />

        <div className="report-applied">
          <strong>Applied filters</strong>
          <p>{applied}</p>
          {empty ? (
            <p className="report-empty-note">No threats found for the selected filters.</p>
          ) : dateIncomplete ? (
            <p className="muted">Select a date (or from/to dates) before generating the PDF.</p>
          ) : (
            <p className="muted">{matchCount ?? 0} matching record(s) will be included.</p>
          )}
        </div>

        <div className="report-export-actions">
          <button
            type="button"
            className="btn btn-primary"
            onClick={() => onGenerate(toQuery(filters))}
            disabled={downloading || dateIncomplete}
          >
            <FileDown size={16} />
            {downloading ? 'Generating PDF…' : 'Generate / Download PDF'}
          </button>
          <button type="button" className="btn btn-ghost" onClick={onClose} disabled={downloading}>
            Cancel
          </button>
          <button
            type="button"
            className="btn btn-secondary"
            onClick={() => setFilters(blankFilters())}
            disabled={downloading}
          >
            <RotateCcw size={16} />
            Reset Filters
          </button>
        </div>
      </div>
    </div>,
    document.body,
  )
}

export default function ReportPanel({ summary, onDownload, downloading }) {
  const [modalOpen, setModalOpen] = useState(false)
  const [filters, setFilters] = useState(blankFilters)
  const [preview, setPreview] = useState(null)

  const latest = summary?.latest_events || []
  const options = useMemo(
    () => ({
      threatTypes: uniqueSorted(Object.keys(summary?.by_type || {})),
      sources: uniqueSorted(Object.keys(summary?.by_source || {})),
      sourceIps: uniqueSorted(Object.keys(summary?.by_device || {})),
    }),
    [summary],
  )

  useEffect(() => {
    if (!modalOpen) return undefined
    let cancelled = false
    api
      .reportPreview(toQuery(filters))
      .then((data) => {
        if (!cancelled) setPreview(data)
      })
      .catch(() => {
        if (!cancelled) setPreview(null)
      })
    return () => {
      cancelled = true
    }
  }, [modalOpen, filters])

  return (
    <div className="panel section">
      <div className="section-head">
        <h3>Decision Support Report</h3>
        <span>Latest threat information, newest first</span>
      </div>

      {!summary ? (
        <div className="empty">Loading report summary…</div>
      ) : (
        <>
          <div className="report-kpi-grid">
            <div className="stat-card total">
              <div className="stat-label">Total</div>
              <div className="stat-value" style={{ fontSize: '1.35rem' }}>
                {summary.total_threats}
              </div>
            </div>
            <div className="stat-card open">
              <div className="stat-label">Open</div>
              <div className="stat-value" style={{ fontSize: '1.35rem' }}>
                {summary.open_threats}
              </div>
            </div>
            <div className="stat-card critical">
              <div className="stat-label">Critical</div>
              <div className="stat-value" style={{ fontSize: '1.35rem' }}>
                {summary.critical_count}
              </div>
            </div>
          </div>

          <p className="muted" style={{ margin: '0.9rem 0 0.55rem', fontSize: '0.9rem' }}>
            Dominant threat: <strong style={{ color: 'var(--text)' }}>{summary.top_threat_type}</strong>
            {summary.generated_at ? (
              <>
                {' '}
                · Updated {formatWhen(summary.generated_at)}
              </>
            ) : null}
          </p>

          <div className="section-head" style={{ marginTop: '0.4rem' }}>
            <h3>Latest records</h3>
            <span>{latest.length ? `${latest.length} newest events` : 'Waiting for events'}</span>
          </div>
          {latest.length ? (
            <div className="report-latest-wrap">
              <table className="report-latest-table">
                <thead>
                  <tr>
                    <th>When</th>
                    <th>Type</th>
                    <th>Severity</th>
                    <th>Source</th>
                    <th>Device</th>
                  </tr>
                </thead>
                <tbody>
                  {latest.map((event) => (
                    <tr key={event.id}>
                      <td className="mono">{formatWhen(event.created_at)}</td>
                      <td>
                        <span className={`badge ${event.threat_type}`}>{event.threat_type}</span>
                      </td>
                      <td>
                        <span className={`badge ${event.severity}`}>{event.severity}</span>
                      </td>
                      <td>{event.source}</td>
                      <td className="mono">{event.source_ip}</td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          ) : (
            <div className="empty">No threats found for the selected filters.</div>
          )}

          <div style={{ display: 'flex', alignItems: 'center', gap: '0.4rem', margin: '0.85rem 0 0.45rem' }}>
            <ShieldAlert size={16} color="#f59e0b" />
            <strong style={{ fontSize: '0.92rem' }}>Recommended actions</strong>
          </div>
          <ul className="report-list">
            {summary.recommendations?.map((rec) => (
              <li key={rec}>{rec}</li>
            ))}
          </ul>

          <div style={{ marginTop: '1rem' }}>
            <button className="btn btn-primary" onClick={() => setModalOpen(true)}>
              <FileDown size={16} />
              Download PDF
            </button>
          </div>
        </>
      )}

      <ExportModal
        open={modalOpen}
        onClose={() => setModalOpen(false)}
        onGenerate={async (query) => {
          await onDownload(query)
          setModalOpen(false)
        }}
        downloading={downloading}
        options={options}
        filters={filters}
        setFilters={setFilters}
        preview={preview}
      />
    </div>
  )
}
