import type { Alert } from "../api";
import { timeFmt } from "../format";

export default function AlertsFeed({ alerts }: { alerts: Alert[] }) {
  return (
    <div className="card">
      <h2>Recent alerts</h2>
      <div className="list">
        {alerts.map((a, i) => (
          <div key={`${a.id ?? i}-${a.ts}`} className={`alert ${a.severity}`}>
            <div>
              <strong>{a.rule}</strong> &middot; {a.src_ip} → {a.dst_ip}{" "}
              <span className="muted">({a.proto})</span>
            </div>
            <div className="meta">
              {timeFmt(a.ts)} &middot; {a.detail}
            </div>
          </div>
        ))}
        {alerts.length === 0 && <div className="muted">all clear</div>}
      </div>
    </div>
  );
}
