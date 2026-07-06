import { useEffect, useState } from "react";
import { type Rule, deleteRule, fetchRules, upsertRule } from "../api";

const empty: Rule = {
  name: "",
  action: "alert",
  severity: "medium",
  description: "",
  match: {},
  enabled: true,
};

export default function RuleEditor() {
  const [rules, setRules] = useState<Rule[]>([]);
  const [draft, setDraft] = useState<Rule>(empty);
  const [error, setError] = useState<string | null>(null);

  async function reload() {
    try {
      setRules(await fetchRules());
    } catch (e) {
      setError(String(e));
    }
  }
  useEffect(() => {
    reload();
  }, []);

  async function save() {
    setError(null);
    if (!draft.name) {
      setError("name is required");
      return;
    }
    try {
      await upsertRule(draft);
      setDraft(empty);
      await reload();
    } catch (e) {
      setError(String(e));
    }
  }

  async function remove(name: string) {
    try {
      await deleteRule(name);
      await reload();
    } catch (e) {
      setError(String(e));
    }
  }

  return (
    <div className="card col-span-2">
      <h2>Filter rules</h2>
      <div className="form-row">
        <label>
          name
          <input value={draft.name} onChange={(e) => setDraft({ ...draft, name: e.target.value })} />
        </label>
        <label>
          action
          <select
            value={draft.action}
            onChange={(e) => setDraft({ ...draft, action: e.target.value as Rule["action"] })}
          >
            <option value="allow">allow</option>
            <option value="drop">drop</option>
            <option value="alert">alert</option>
          </select>
        </label>
        <label>
          severity
          <select
            value={draft.severity}
            onChange={(e) => setDraft({ ...draft, severity: e.target.value as Rule["severity"] })}
          >
            <option value="low">low</option>
            <option value="medium">medium</option>
            <option value="high">high</option>
          </select>
        </label>
        <label>
          src CIDR
          <input
            value={draft.match.src_cidr ?? ""}
            onChange={(e) => setDraft({ ...draft, match: { ...draft.match, src_cidr: e.target.value || null } })}
          />
        </label>
        <label>
          dst CIDR
          <input
            value={draft.match.dst_cidr ?? ""}
            onChange={(e) => setDraft({ ...draft, match: { ...draft.match, dst_cidr: e.target.value || null } })}
          />
        </label>
        <label>
          proto
          <input
            placeholder="HTTP / TLS / DNS / TCP / UDP"
            value={draft.match.proto ?? ""}
            onChange={(e) => setDraft({ ...draft, match: { ...draft.match, proto: e.target.value || null } })}
          />
        </label>
        <label>
          dst port
          <input
            type="number"
            value={draft.match.dst_port ?? ""}
            onChange={(e) =>
              setDraft({
                ...draft,
                match: {
                  ...draft.match,
                  dst_port: e.target.value === "" ? null : Number(e.target.value),
                },
              })
            }
          />
        </label>
        <label>
          SNI regex
          <input
            value={draft.match.sni_regex ?? ""}
            onChange={(e) =>
              setDraft({ ...draft, match: { ...draft.match, sni_regex: e.target.value || null } })
            }
          />
        </label>
      </div>
      <div style={{ display: "flex", gap: 8, marginTop: 4 }}>
        <button className="primary" onClick={save}>
          save rule
        </button>
        {error && <span className="muted">{error}</span>}
      </div>

      <table style={{ marginTop: 14 }}>
        <thead>
          <tr>
            <th>Name</th>
            <th>Action</th>
            <th>Sev</th>
            <th>Match</th>
            <th></th>
          </tr>
        </thead>
        <tbody>
          {rules.map((r) => (
            <tr key={r.name}>
              <td>{r.name}</td>
              <td>{r.action}</td>
              <td>{r.severity}</td>
              <td className="muted">{summarize(r)}</td>
              <td>
                <button className="danger" onClick={() => remove(r.name)}>
                  delete
                </button>
              </td>
            </tr>
          ))}
          {rules.length === 0 && (
            <tr>
              <td colSpan={5} className="muted">
                no rules — add one above
              </td>
            </tr>
          )}
        </tbody>
      </table>
    </div>
  );
}

function summarize(r: Rule): string {
  const m = r.match;
  return (
    Object.entries(m)
      .filter(([, v]) => v !== null && v !== undefined && v !== "")
      .map(([k, v]) => `${k}=${v}`)
      .join(" ") || "(any)"
  );
}
