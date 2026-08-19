export default function CollectionJobs({ jobs }) {
  const rows = jobs || []

  return (
    <div className="panel section">
      <div className="section-head">
        <h3>Collection Jobs</h3>
        <span>Recent simultaneous sweeps</span>
      </div>
      {rows.length === 0 ? (
        <p className="muted source-copy">No collection jobs yet. Use Collect From All Sources to start Step 1.</p>
      ) : (
        <div className="jobs-table-wrap">
          <table className="jobs-table">
            <thead>
              <tr>
                <th>Job</th>
                <th>Mode</th>
                <th>Sources</th>
                <th>Events</th>
                <th>Status</th>
              </tr>
            </thead>
            <tbody>
              {rows.map((job) => (
                <tr key={job.id}>
                  <td className="mono">#{job.id}</td>
                  <td>{job.mode || 'network'}</td>
                  <td className="mono">{job.sources_scanned}</td>
                  <td className="mono">{job.events_collected}</td>
                  <td>
                    <span className={`job-status ${job.status}`}>{job.status}</span>
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
          {rows[0]?.message ? <p className="job-last-msg">{rows[0].message}</p> : null}
        </div>
      )}
    </div>
  )
}
