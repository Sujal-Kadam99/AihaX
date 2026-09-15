import { useEffect, useState } from 'react';
import { Link, useNavigate } from 'react-router-dom';
import { getScanHistory } from '../lib/api';
import { Table, TableHeader, TableBody, TableRow, TableHead, TableCell } from '../components/ui/Table';
import Badge from '../components/ui/Badge';
import Skeleton from '../components/ui/Skeleton';
import EmptyState from '../components/ui/EmptyState';

export default function ScanHistory() {
  const [scans, setScans] = useState([]);
  const [loading, setLoading] = useState(true);
  const navigate = useNavigate();

  useEffect(() => {
    getScanHistory()
      .then((res) => setScans(res.data))
      .catch(() => setScans([]))
      .finally(() => setLoading(false));
  }, []);

  const getStatusVariant = (status) => {
    switch (status) {
      case 'complete': return 'success';
      case 'running': return 'info';
      case 'error': return 'destructive';
      default: return 'secondary';
    }
  };

  return (
    <div className="p-6 max-w-5xl mx-auto space-y-6">
      <h1 className="font-display text-2xl font-bold text-text-primary">Scan History</h1>

      {loading ? (
        <div className="space-y-3">
          {[1, 2, 3, 4].map((i) => (
            <Skeleton key={i} className="h-12 w-full" />
          ))}
        </div>
      ) : scans.length === 0 ? (
        <EmptyState
          title="No Past Assessments"
          description="You have not launched any security scans yet."
          actionLabel="Start New Scan"
          onAction={() => navigate('/new-scan')}
        />
      ) : (
        <Table>
          <TableHeader>
            <TableRow>
              <TableHead>Target URL</TableHead>
              <TableHead>Date</TableHead>
              <TableHead>Depth</TableHead>
              <TableHead>Total Findings</TableHead>
              <TableHead>Risk Score</TableHead>
              <TableHead>Status</TableHead>
            </TableRow>
          </TableHeader>
          <TableBody>
            {scans.map((scan) => (
              <TableRow key={scan.id}>
                <TableCell>
                  <Link
                    to={scan.status === 'complete' ? `/findings/${scan.id}` : `/scan/${scan.id}`}
                    className="text-accent hover:underline font-mono text-xs"
                  >
                    {scan.target_url}
                  </Link>
                </TableCell>
                <TableCell className="text-text-secondary text-xs">
                  {new Date(scan.created_at).toLocaleString()}
                </TableCell>
                <TableCell className="capitalize text-xs text-text-secondary">{scan.scan_depth}</TableCell>
                <TableCell className="font-display text-xs">{scan.total_findings}</TableCell>
                <TableCell className="font-display text-xs">{scan.risk_score ?? '—'}</TableCell>
                <TableCell>
                  <Badge variant={getStatusVariant(scan.status)}>{scan.status}</Badge>
                </TableCell>
              </TableRow>
            ))}
          </TableBody>
        </Table>
      )}
    </div>
  );
}
