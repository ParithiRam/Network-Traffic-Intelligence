export type Severity = "low" | "medium" | "high";
export type Action = "allow" | "drop" | "alert";

export interface RuleMatch {
  src_cidr?: string | null;
  dst_cidr?: string | null;
  src_port?: number | null;
  dst_port?: number | null;
  proto?: string | null;
  sni_regex?: string | null;
  host_regex?: string | null;
  direction?: "internal" | "external" | "inbound" | "outbound" | null;
}

export interface Rule {
  name: string;
  action: Action;
  severity: Severity;
  description?: string;
  match: RuleMatch;
  enabled?: boolean;
}

export interface Alert {
  id?: number;
  ts: number;
  rule: string;
  severity: Severity;
  src_ip: string;
  dst_ip: string;
  proto: string;
  detail: string;
}

export interface MetricsSnapshot {
  generated_at: number;
  total_packets: number;
  total_bytes: number;
  dropped_packets: number;
  alerts_count: number;
  top_talkers: { ip: string; bytes: number; packets: number }[];
  protocols: { proto: string; bytes: number; packets: number }[];
  bandwidth: { ts: number; bytes: number; packets: number }[];
}

const base = "";

export async function fetchMetrics(): Promise<MetricsSnapshot> {
  const r = await fetch(`${base}/api/metrics`);
  if (!r.ok) throw new Error("metrics fetch failed");
  return r.json();
}

export async function fetchAlerts(limit = 100): Promise<Alert[]> {
  const r = await fetch(`${base}/api/alerts?limit=${limit}`);
  if (!r.ok) throw new Error("alerts fetch failed");
  return r.json();
}

export async function fetchRules(): Promise<Rule[]> {
  const r = await fetch(`${base}/api/rules`);
  if (!r.ok) throw new Error("rules fetch failed");
  return r.json();
}

export async function upsertRule(rule: Rule): Promise<Rule> {
  const r = await fetch(`${base}/api/rules`, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify(rule),
  });
  if (!r.ok) throw new Error(`rule upsert failed: ${r.status}`);
  return r.json();
}

export async function deleteRule(name: string): Promise<void> {
  const r = await fetch(`${base}/api/rules/${encodeURIComponent(name)}`, { method: "DELETE" });
  if (!r.ok && r.status !== 204) throw new Error(`rule delete failed: ${r.status}`);
}

export function openStream(handlers: {
  onMetrics?: (m: MetricsSnapshot) => void;
  onAlert?: (a: Alert) => void;
  onPacket?: (p: any) => void;
  onStatus?: (live: boolean) => void;
}): () => void {
  const proto = window.location.protocol === "https:" ? "wss" : "ws";
  const ws = new WebSocket(`${proto}://${window.location.host}/ws/stream`);
  ws.onopen = () => handlers.onStatus?.(true);
  ws.onclose = () => handlers.onStatus?.(false);
  ws.onerror = () => handlers.onStatus?.(false);
  ws.onmessage = (ev) => {
    const msg = JSON.parse(ev.data);
    if (msg.type === "metrics") handlers.onMetrics?.(msg.data);
    else if (msg.type === "alert") handlers.onAlert?.(msg.data);
    else if (msg.type === "packet") handlers.onPacket?.(msg.data);
  };
  return () => ws.close();
}
