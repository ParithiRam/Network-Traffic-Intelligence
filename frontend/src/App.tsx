import { useEffect, useRef, useState } from "react";
import { type Alert, type MetricsSnapshot, fetchAlerts, fetchMetrics, openStream } from "./api";
import AlertsFeed from "./components/AlertsFeed";
import BandwidthChart from "./components/BandwidthChart";
import ProtocolPie from "./components/ProtocolPie";
import RuleEditor from "./components/RuleEditor";
import TopTalkers from "./components/TopTalkers";
import { bytes, nicenum } from "./format";

const MAX_ALERTS = 80;

export default function App() {
  const [metrics, setMetrics] = useState<MetricsSnapshot | null>(null);
  const [alerts, setAlerts] = useState<Alert[]>([]);
  const [live, setLive] = useState(false);
  const closeRef = useRef<(() => void) | null>(null);

  useEffect(() => {
    fetchMetrics().then(setMetrics).catch(() => {});
    fetchAlerts(50).then(setAlerts).catch(() => {});
    closeRef.current = openStream({
      onMetrics: setMetrics,
      onAlert: (a) =>
        setAlerts((prev) => [a, ...prev].slice(0, MAX_ALERTS)),
      onStatus: setLive,
    });
    return () => closeRef.current?.();
  }, []);

  return (
    <div className="app">
      <header className="topbar">
        <h1>NTI · Network Traffic Intelligence</h1>
        <span className="badge">
          <span className={`dot ${live ? "live" : "dead"}`} /> {live ? "streaming" : "disconnected"}
        </span>
        <span className="badge muted">
          export:{" "}
          <a href="/api/export/cef?limit=1000">CEF</a> ·{" "}
          <a href="/api/export/jsonl?limit=1000">JSONL</a>
        </span>
      </header>

      <div className="grid">
        <div className="card col-span-2">
          <h2>Overview</h2>
          <div className="kpis">
            <div className="kpi">
              <div className="label">packets</div>
              <div className="value">{metrics ? nicenum(metrics.total_packets) : "—"}</div>
            </div>
            <div className="kpi">
              <div className="label">bytes</div>
              <div className="value">{metrics ? bytes(metrics.total_bytes) : "—"}</div>
            </div>
            <div className="kpi">
              <div className="label">dropped</div>
              <div className="value">{metrics ? nicenum(metrics.dropped_packets) : "—"}</div>
            </div>
            <div className="kpi">
              <div className="label">alerts</div>
              <div className="value">{metrics ? nicenum(metrics.alerts_count) : "—"}</div>
            </div>
          </div>
        </div>

        <BandwidthChart metrics={metrics} />
        <ProtocolPie metrics={metrics} />
        <TopTalkers metrics={metrics} />
        <AlertsFeed alerts={alerts} />
        <RuleEditor />
      </div>
    </div>
  );
}
