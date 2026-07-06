import type { MetricsSnapshot } from "../api";
import { bytes, nicenum } from "../format";

export default function TopTalkers({ metrics }: { metrics: MetricsSnapshot | null }) {
  const rows = metrics?.top_talkers ?? [];
  return (
    <div className="card">
      <h2>Top talkers</h2>
      <table>
        <thead>
          <tr>
            <th>Source IP</th>
            <th>Packets</th>
            <th>Bytes</th>
          </tr>
        </thead>
        <tbody>
          {rows.map((t) => (
            <tr key={t.ip}>
              <td>{t.ip}</td>
              <td>{nicenum(t.packets)}</td>
              <td>{bytes(t.bytes)}</td>
            </tr>
          ))}
          {rows.length === 0 && (
            <tr>
              <td colSpan={3} className="muted">
                no traffic yet
              </td>
            </tr>
          )}
        </tbody>
      </table>
    </div>
  );
}
