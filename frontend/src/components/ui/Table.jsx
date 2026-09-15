import { cn } from '../../lib/utils';

export function Table({ className = '', children, ...props }) {
  return (
    <div className="w-full overflow-x-auto rounded border border-border">
      <table className={cn('w-full text-left border-collapse text-sm', className)} {...props}>
        {children}
      </table>
    </div>
  );
}

export function TableHeader({ className = '', children, ...props }) {
  return (
    <thead className={cn('bg-surface-2 border-b border-border text-xs uppercase text-text-secondary font-medium', className)} {...props}>
      {children}
    </thead>
  );
}

export function TableBody({ className = '', children, ...props }) {
  return <tbody className={cn('divide-y divide-border-subtle bg-surface', className)} {...props}>{children}</tbody>;
}

export function TableRow({ className = '', children, ...props }) {
  return (
    <tr className={cn('hover:bg-surface-hover/50 transition-colors', className)} {...props}>
      {children}
    </tr>
  );
}

export function TableHead({ className = '', children, ...props }) {
  return (
    <th className={cn('px-4 py-3 font-semibold text-text-secondary', className)} {...props}>
      {children}
    </th>
  );
}

export function TableCell({ className = '', children, ...props }) {
  return (
    <td className={cn('px-4 py-3 text-text-primary align-middle', className)} {...props}>
      {children}
    </td>
  );
}

export function TableFooter({ className = '', children, ...props }) {
  return (
    <tfoot className={cn('bg-surface-2 font-medium text-text-secondary border-t border-border', className)} {...props}>
      {children}
    </tfoot>
  );
}

export default Table;
