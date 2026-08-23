import { useEffect, useMemo, useState } from "react";
import { ApiError, type Client, type SQLResult, type SQLTable } from "./api";

const initialQuery = `SELECT id, platform, mode, disabled, updated_at
FROM oarlock_devices
ORDER BY id
LIMIT 100`;

export function SQLExplorer({ client }: { client: Client }) {
  const [tables, setTables] = useState<SQLTable[]>([]);
  const [query, setQuery] = useState(initialQuery);
  const [result, setResult] = useState<SQLResult | null>(null);
  const [history, setHistory] = useState<string[]>([]);
  const [running, setRunning] = useState(false);
  const [error, setError] = useState("");
  const [schemaFilter, setSchemaFilter] = useState("");

  useEffect(() => {
    let active = true;
    client.sqlSchema().then(({ tables: next }) => {
      if (active) setTables(next);
    }).catch((caught: unknown) => {
      if (active) setError(messageFor(caught));
    });
    return () => { active = false; };
  }, [client]);

  const visibleTables = useMemo(() => {
    const needle = schemaFilter.trim().toLowerCase();
    if (!needle) return tables;
    return tables.filter((table) => table.name.toLowerCase().includes(needle)
      || table.columns.some((column) => column.name.toLowerCase().includes(needle)));
  }, [schemaFilter, tables]);

  async function run() {
    if (!query.trim() || running) return;
    setRunning(true);
    setError("");
    try {
      const next = await client.sqlQuery(query);
      setResult(next);
      setHistory((current) => [query, ...current.filter((item) => item !== query)].slice(0, 8));
    } catch (caught) {
      setResult(null);
      setError(messageFor(caught));
    } finally {
      setRunning(false);
    }
  }

  function selectTable(table: SQLTable) {
    setQuery(`SELECT *\nFROM ${table.name}\nLIMIT 100`);
    setError("");
  }

  function exportCSV() {
    if (!result) return;
    const lines = [result.columns, ...result.rows]
      .map((row) => row.map(csvCell).join(","))
      .join("\n");
    const link = document.createElement("a");
    link.href = URL.createObjectURL(new Blob([lines], { type: "text/csv;charset=utf-8" }));
    link.download = `oarlock-query-${new Date().toISOString().replace(/[:.]/g, "-")}.csv`;
    link.click();
    URL.revokeObjectURL(link.href);
  }

  return (
    <div className="grid min-h-[42rem] overflow-hidden rounded-lg border border-border bg-bg-raised shadow-sm lg:grid-cols-[15rem_minmax(0,1fr)]" data-testid="sql-explorer">
      <aside className="border-b border-border bg-bg lg:border-b-0 lg:border-r">
        <div className="border-b border-border p-3">
          <input
            className="field"
            value={schemaFilter}
            onChange={(event) => setSchemaFilter(event.target.value)}
            placeholder="Filter schema"
            aria-label="Filter schema"
          />
        </div>
        <div className="max-h-64 overflow-auto p-2 lg:max-h-[36rem]">
          {visibleTables.map((table) => (
            <button
              key={table.name}
              type="button"
              className="w-full rounded-md px-2 py-2 text-left hover:bg-bg-raised"
              onClick={() => selectTable(table)}
            >
              <span className="mono block truncate text-xs font-semibold">{table.name}</span>
              <span className="mt-1 block truncate text-[11px] text-fg-faint">
                {table.columns.length} columns
              </span>
            </button>
          ))}
          {visibleTables.length === 0 && (
            <p className="p-2 text-xs text-fg-muted">No matching tables.</p>
          )}
        </div>
      </aside>

      <div className="flex min-w-0 flex-col">
        <div className="border-b border-border p-4">
          <div className="mb-3 flex items-center justify-between gap-3">
            <div>
              <h2 className="text-sm font-semibold">Query</h2>
              <p className="text-xs text-fg-muted">Read-only operational data</p>
            </div>
            <button className="btn btn-primary" disabled={running || !query.trim()} onClick={() => void run()} data-testid="run-sql">
              {running ? "Running" : "Run"}
            </button>
          </div>
          <textarea
            className="field mono min-h-36 resize-y text-xs leading-5"
            value={query}
            onChange={(event) => setQuery(event.target.value)}
            onKeyDown={(event) => {
              if ((event.metaKey || event.ctrlKey) && event.key === "Enter") {
                event.preventDefault();
                void run();
              }
            }}
            spellCheck={false}
            aria-label="SQL query"
          />
          {error && (
            <p className="mt-3 rounded-md border border-state-refused/40 px-3 py-2 text-sm text-state-refused" role="alert">
              {error}
            </p>
          )}
        </div>

        <div className="flex min-h-0 flex-1 flex-col">
          <div className="flex min-h-12 items-center justify-between gap-3 border-b border-border px-4">
            <div className="flex items-center gap-3">
              <h2 className="text-sm font-semibold">Results</h2>
              {result && (
                <span className="mono text-[11px] text-fg-faint">
                  {result.rows.length}{result.truncated ? "+" : ""} rows · {result.duration_ms} ms
                </span>
              )}
            </div>
            <button className="btn" disabled={!result || result.rows.length === 0} onClick={exportCSV}>
              Export CSV
            </button>
          </div>
          <div className="min-h-64 flex-1 overflow-auto">
            {result ? <ResultTable result={result} /> : (
              <div className="grid min-h-64 place-items-center p-6 text-sm text-fg-muted">
                Run a query to view results.
              </div>
            )}
          </div>
        </div>

        {history.length > 0 && (
          <details className="border-t border-border px-4 py-3">
            <summary className="cursor-pointer text-xs font-semibold text-fg-muted">Recent in this tab</summary>
            <div className="mt-2 grid gap-1">
              {history.map((item) => (
                <button key={item} className="mono truncate rounded px-2 py-1.5 text-left text-[11px] hover:bg-bg" onClick={() => setQuery(item)}>
                  {item.replace(/\s+/g, " ")}
                </button>
              ))}
            </div>
          </details>
        )}
      </div>
    </div>
  );
}

function ResultTable({ result }: { result: SQLResult }) {
  return (
    <table className="w-max min-w-full border-collapse text-left text-xs">
      <thead className="sticky top-0 z-10 bg-bg">
        <tr>
          {result.columns.map((column, index) => (
            <th key={`${column}-${index}`} className="mono border-b border-r border-border px-3 py-2 font-semibold last:border-r-0">
              {column}
            </th>
          ))}
        </tr>
      </thead>
      <tbody>
        {result.rows.map((row, rowIndex) => (
          <tr key={rowIndex} className="odd:bg-bg-raised even:bg-bg">
            {row.map((value, columnIndex) => (
              <td key={columnIndex} className="mono max-w-96 border-b border-r border-border px-3 py-2 align-top last:border-r-0">
                <span className="block overflow-hidden text-ellipsis whitespace-nowrap" title={display(value)}>{display(value)}</span>
              </td>
            ))}
          </tr>
        ))}
      </tbody>
    </table>
  );
}

function display(value: unknown): string {
  if (value === null) return "NULL";
  if (typeof value === "object") return JSON.stringify(value);
  return String(value);
}

function csvCell(value: unknown): string {
  const text = display(value);
  return `"${text.replace(/"/g, '""')}"`;
}

function messageFor(error: unknown): string {
  if (error instanceof ApiError) return error.detail || error.message;
  return error instanceof Error ? error.message : String(error);
}
