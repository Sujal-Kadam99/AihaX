export function parsePortScope(input) {
  const entries = String(input || '').split(',').map((entry) => entry.trim()).filter(Boolean);
  const ports = new Set();

  for (const entry of entries) {
    const match = entry.match(/^(\d+)(?:\s*-\s*(\d+))?$/);
    if (!match) throw new Error(`Invalid port entry: ${entry}`);
    const start = Number(match[1]);
    const end = match[2] ? Number(match[2]) : start;
    if (start < 1 || end > 65535) throw new Error('Ports must be in the range 1 through 65535.');
    if (start > end) throw new Error(`Invalid port range: ${entry}`);
    for (let port = start; port <= end; port += 1) ports.add(port);
  }

  return [...ports].sort((a, b) => a - b);
}

export function formatPortScope(ports = []) {
  const sorted = [...new Set(ports.map(Number).filter((port) => port >= 1 && port <= 65535))].sort((a, b) => a - b);
  if (!sorted.length) return 'none configured';
  const ranges = [];
  let start = sorted[0];
  let previous = start;
  for (const port of sorted.slice(1)) {
    if (port === previous + 1) {
      previous = port;
      continue;
    }
    ranges.push(start === previous ? String(start) : `${start}-${previous}`);
    start = previous = port;
  }
  ranges.push(start === previous ? String(start) : `${start}-${previous}`);
  return ranges.join(', ');
}
