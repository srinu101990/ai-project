export default function ClientBanner({ agentStatus }) {
  const live = (agentStatus?.agents || []).filter((pc) => pc.online)
  if (!live.length) {
    return (
      <div className="client-banner idle" role="status">
        <strong>Second laptop: not LIVE</strong>
        <span>
          Keep <code>sentinel_agent.py</code> running on the other PC (do not close it after
          --inject). Then this bar shows that hostname and IP.
        </span>
      </div>
    )
  }

  return (
    <div className="client-banner live" role="status">
      {live.map((pc) => (
        <div key={`${pc.hostname}-${pc.source_ip}`}>
          <strong>LIVE CLIENT {pc.hostname}</strong>
          <span className="mono"> {pc.source_ip}</span>
        </div>
      ))}
    </div>
  )
}
