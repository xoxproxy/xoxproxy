import { useMemo, useState } from "react";
import { EmptyState, Spinner } from "./ui";

export interface Column<T> {
  key: string;
  header: string;
  render: (row: T) => React.ReactNode;
  sortValue?: (row: T) => string | number;
  align?: "left" | "right";
  className?: string;
}

// DataTable: sortable columns, loading and empty states, optional row
// click. Styling stays minimal per the tokens; density is comfortable.
export default function DataTable<T>({
  columns,
  rows,
  loading,
  emptyLabel = "Nothing here yet",
  onRowClick,
  rowKey,
}: {
  columns: Column<T>[];
  rows: T[];
  loading?: boolean;
  emptyLabel?: string;
  onRowClick?: (row: T) => void;
  rowKey: (row: T) => string | number;
}) {
  const [sort, setSort] = useState<{ key: string; dir: 1 | -1 } | null>(null);

  const sorted = useMemo(() => {
    if (!sort) return rows;
    const col = columns.find((c) => c.key === sort.key);
    if (!col?.sortValue) return rows;
    const val = col.sortValue;
    return [...rows].sort((a, b) => {
      const av = val(a), bv = val(b);
      if (av === bv) return 0;
      return (av < bv ? -1 : 1) * sort.dir;
    });
  }, [rows, sort, columns]);

  const toggleSort = (key: string) => {
    setSort((s) =>
      s?.key === key
        ? s.dir === 1
          ? { key, dir: -1 }
          : null // third click clears
        : { key, dir: 1 },
    );
  };

  if (loading) return <Spinner />;
  if (rows.length === 0) return <EmptyState label={emptyLabel} />;

  return (
    <div className="overflow-x-auto rounded-[--radius-lg] border border-line-2 bg-surface-1 shadow-card">
      <table className="w-full border-collapse text-[length:var(--font-sp)]">
        <thead>
          <tr className="border-b border-line-2 text-left">
            {columns.map((col) => (
              <th
                key={col.key}
                className={[
                  "px-4 py-[10px] text-[length:var(--font-xs)] font-semibold uppercase tracking-wide text-caption",
                  col.align === "right" ? "text-right" : "text-left",
                  col.sortValue
                    ? "cursor-pointer select-none hover:text-secondary"
                    : "",
                  col.className ?? "",
                ].join(" ")}
                onClick={col.sortValue ? () => toggleSort(col.key) : undefined}
                aria-sort={
                  sort?.key === col.key
                    ? sort.dir === 1
                      ? "ascending"
                      : "descending"
                    : undefined
                }
              >
                {col.header}
                {sort?.key === col.key && (
                  <span className="ml-1" aria-hidden>
                    {sort.dir === 1 ? "↑" : "↓"}
                  </span>
                )}
              </th>
            ))}
          </tr>
        </thead>
        <tbody>
          {sorted.map((row) => (
            <tr
              key={rowKey(row)}
              onClick={onRowClick ? () => onRowClick(row) : undefined}
              className={[
                "border-b border-line-1 last:border-0 transition-colors duration-[var(--duration-fast)]",
                onRowClick ? "cursor-pointer hover:bg-[var(--interactive-hover)]" : "",
              ].join(" ")}
            >
              {columns.map((col) => (
                <td
                  key={col.key}
                  className={[
                    "px-4 py-[10px]",
                    col.align === "right" ? "text-right" : "text-left",
                  ].join(" ")}
                >
                  {col.render(row)}
                </td>
              ))}
            </tr>
          ))}
        </tbody>
      </table>
    </div>
  );
}
