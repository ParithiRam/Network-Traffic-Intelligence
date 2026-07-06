import { Area, AreaChart, ResponsiveContainer, Tooltip, XAxis, YAxis } from "recharts";
import type { MetricsSnapshot } from "../api";
import { bytes, timeFmt } from "../format";

export default function BandwidthChart({ metrics }: { metrics: MetricsSnapshot | null }) {
  const data = (metrics?.bandwidth ?? []).map((p) => ({
    ts: p.ts,
    label: timeFmt(p.ts),
    bps: p.bytes,
  }));
  return (
    <div className="card col-span-2">
      <h2>Bandwidth (bytes / second)</h2>
      <div style={{ height: 220 }}>
        <ResponsiveContainer width="100%" height="100%">
          <AreaChart data={data} margin={{ top: 4, right: 8, bottom: 0, left: 8 }}>
            <defs>
              <linearGradient id="bwfill" x1="0" y1="0" x2="0" y2="1">
                <stop offset="0%" stopColor="#5b8cff" stopOpacity={0.7} />
                <stop offset="100%" stopColor="#5b8cff" stopOpacity={0.05} />
              </linearGradient>
            </defs>
            <XAxis dataKey="label" stroke="#92a0c8" fontSize={11} minTickGap={40} />
            <YAxis stroke="#92a0c8" fontSize={11} tickFormatter={bytes} width={70} />
            <Tooltip
              contentStyle={{ background: "#131a2e", border: "1px solid #243056" }}
              formatter={(v: number) => [bytes(v), "bytes/sec"]}
            />
            <Area type="monotone" dataKey="bps" stroke="#5b8cff" fill="url(#bwfill)" />
          </AreaChart>
        </ResponsiveContainer>
      </div>
    </div>
  );
}
