import { useEffect, useState } from "react";
import { ApiError, Client, type SSHInfo } from "./api";

function errorText(error: unknown): string {
  if (error instanceof ApiError) return error.detail || error.message;
  return error instanceof Error ? error.message : String(error);
}

function sshHost(host: string): string {
  return host.includes(":") && !host.startsWith("[") ? `[${host}]` : host;
}

export function SSHAccess({ client, device }: { client: Client; device: string }) {
  const [open, setOpen] = useState(false);
  const [info, setInfo] = useState<SSHInfo | null>(null);
  const [identity, setIdentity] = useState("~/.ssh/id_ed25519");
  const [error, setError] = useState("");
  const [copied, setCopied] = useState(false);

  useEffect(() => {
    if (!open || info) return;
    client.sshInfo().then(setInfo).catch((caught) => setError(errorText(caught)));
  }, [client, info, open]);

  const target = device.trim();
  const command = info && target
    ? `ssh -p ${info.port} -i ${identity || "~/.ssh/id_ed25519"} -o UserKnownHostsFile=~/Downloads/oarlock_known_hosts.txt ${target}@${sshHost(info.host)}`
    : "";

  function downloadHostKey() {
    if (!info) return;
    const url = URL.createObjectURL(new Blob([info.known_hosts + "\n"], { type: "text/plain" }));
    const link = document.createElement("a");
    link.href = url;
    link.download = "oarlock_known_hosts.txt";
    link.click();
    URL.revokeObjectURL(url);
  }

  async function copyCommand() {
    if (!command) return;
    await navigator.clipboard.writeText(command);
    setCopied(true);
    window.setTimeout(() => setCopied(false), 1500);
  }

  return (
    <>
      <button className="btn" disabled={!target} onClick={() => setOpen(true)}>SSH client</button>
      {open && (
        <div className="fixed inset-0 z-50 grid place-items-center bg-black/35 p-4" role="presentation"
          onMouseDown={() => setOpen(false)}>
          <section className="w-full max-w-2xl rounded-lg border border-border bg-bg-raised p-6 shadow-2xl"
            role="dialog" aria-modal="true" aria-labelledby="ssh-client-title"
            onMouseDown={(event) => event.stopPropagation()}>
            <div className="flex items-start justify-between gap-4">
              <div>
                <h2 id="ssh-client-title" className="text-lg font-semibold">Local SSH client</h2>
                <p className="mt-1 text-sm text-fg-muted">{target}</p>
              </div>
              <button className="icon-btn" onClick={() => setOpen(false)} aria-label="Close SSH client dialog" title="Close">x</button>
            </div>
            {error && <p className="mt-5 text-sm text-state-refused" role="alert">{error}</p>}
            {!info && !error && <p className="mt-5 text-sm text-fg-muted">Loading SSH connection details...</p>}
            {info && (
              <div className="mt-5 grid gap-4">
                <label className="grid gap-1">
                  <span className="text-[11px] font-semibold uppercase tracking-wider text-fg-faint">Operator identity file</span>
                  <input className="field mono" value={identity} onChange={(event) => setIdentity(event.target.value)} />
                </label>
                <div>
                  <div className="mb-1 text-[11px] font-semibold uppercase tracking-wider text-fg-faint">Command</div>
                  <pre className="overflow-x-auto rounded-md border border-border bg-bg p-3 text-sm"><code>{command}</code></pre>
                </div>
                <dl className="grid grid-cols-[auto_minmax(0,1fr)] gap-x-4 gap-y-2 text-sm">
                  <dt className="text-fg-faint">Principal</dt><dd className="mono truncate">{info.principal}</dd>
                  <dt className="text-fg-faint">Gateway</dt><dd className="mono">{info.host}:{info.port}</dd>
                  <dt className="text-fg-faint">Fingerprint</dt><dd className="mono break-all">{info.fingerprint}</dd>
                </dl>
                <p className="text-sm text-fg-muted">The download contains the gateway public host key. Your operator private key remains on this computer.</p>
                <div className="flex flex-wrap justify-end gap-2 border-t border-border pt-4">
                  <button className="btn" onClick={downloadHostKey}>Download host key</button>
                  <button className="btn btn-primary" onClick={() => void copyCommand()}>{copied ? "Copied" : "Copy command"}</button>
                </div>
              </div>
            )}
          </section>
        </div>
      )}
    </>
  );
}
