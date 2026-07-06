import { Cell, Pie, PieChart, ResponsiveContainer, Tooltip } from "recharts";
import type { MetricsSnapshot } from "../api";
import { nicenum } from "../format";

const COLORS = ["#5b8cff", "#4ade80", "#facc15", "#f87171", "#a78bfa", "#22d3ee", "#fb923c"];

export default function ProtocolPie({ metrics }: { metrics: MetricsSnapshot | null }) {
  const data = (metrics?.protocols ?? []).map((p) => ({ name: p.proto, value: p.packets }));
  return (
    <div className="card">
      <h2>Protocol distribution</h2>
      <div style={{ height: 220 }}>
        <ResponsiveContainer width="100%" height="100%">
          <PieChart>
            <Pie data={data} dataKey="value" nameKey="name" innerRadius={45} outerRadius={80}>
              {data.map((_, i) => (
                <Cell key={i} fill={COLORS[i % COLORS.length]} stroke="#0b1020" />
              ))}
            </Pie>
            <Tooltip
              contentStyle={{ background: "#131a2e", border: "1px solid #243056" }}
              formatter={(v: number, name: string) => [nicenum(v) + " pkts", name]}
            />
          </PieChart>
        </ResponsiveContainer>
      </div>
    </div>
  );
}
