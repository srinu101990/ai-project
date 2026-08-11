/** Deterministic Indian-city mapping for threat visualization. */
const CITIES = [
  'Jaipur',
  'Bengaluru',
  'Chennai',
  'Delhi',
  'Hyderabad',
  'Kochi',
  'Mumbai',
  'Pune',
]

export function cityForThreat(threat) {
  const key = `${threat?.source_ip || ''}|${threat?.id || 0}|${threat?.source || ''}`
  let hash = 0
  for (let i = 0; i < key.length; i += 1) {
    hash = (hash * 31 + key.charCodeAt(i)) >>> 0
  }
  return CITIES[hash % CITIES.length]
}

export function threatsByCity(threats = []) {
  const counts = Object.fromEntries(CITIES.map((city) => [city, 0]))
  threats.forEach((threat) => {
    const city = cityForThreat(threat)
    counts[city] = (counts[city] || 0) + 1
  })
  return Object.entries(counts)
    .map(([name, value]) => ({ name, value }))
    .filter((row) => row.value > 0)
    .sort((a, b) => b.value - a.value)
}
