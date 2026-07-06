"""nti CLI — manage rules and tail alerts.

Talks to a running backend over HTTP so it works the same in dev, Docker, or
when the dashboard is the source of truth.
"""
from __future__ import annotations

import asyncio
import json
import os
from typing import Optional

import httpx
import typer
import yaml

from .models import Rule, RuleMatch

app = typer.Typer(add_completion=False, no_args_is_help=True)
rules_app = typer.Typer(help="Manage filter rules")
alerts_app = typer.Typer(help="Inspect alerts")
app.add_typer(rules_app, name="rules")
app.add_typer(alerts_app, name="alerts")

DEFAULT_BASE = os.getenv("NTI_BASE_URL", "http://localhost:8000")


def _client() -> httpx.Client:
    return httpx.Client(base_url=DEFAULT_BASE, timeout=10.0)


@rules_app.command("list")
def rules_list() -> None:
    """List all rules from the running backend."""
    with _client() as c:
        r = c.get("/api/rules")
        r.raise_for_status()
        typer.echo(yaml.safe_dump({"rules": r.json()}, sort_keys=False))


@rules_app.command("add")
def rules_add(
    name: str = typer.Argument(...),
    action: str = typer.Option("alert", help="allow|drop|alert"),
    severity: str = typer.Option("medium", help="low|medium|high"),
    src_cidr: Optional[str] = typer.Option(None),
    dst_cidr: Optional[str] = typer.Option(None),
    proto: Optional[str] = typer.Option(None),
    dst_port: Optional[int] = typer.Option(None),
    sni_regex: Optional[str] = typer.Option(None),
    host_regex: Optional[str] = typer.Option(None),
    direction: Optional[str] = typer.Option(None, help="internal|external|inbound|outbound"),
    description: str = typer.Option(""),
) -> None:
    """Create or replace a rule."""
    rule = Rule(
        name=name,
        action=action,  # type: ignore[arg-type]
        severity=severity,  # type: ignore[arg-type]
        description=description,
        match=RuleMatch(
            src_cidr=src_cidr,
            dst_cidr=dst_cidr,
            proto=proto,
            dst_port=dst_port,
            sni_regex=sni_regex,
            host_regex=host_regex,
            direction=direction,  # type: ignore[arg-type]
        ),
    )
    with _client() as c:
        r = c.post("/api/rules", json=rule.model_dump())
        r.raise_for_status()
        typer.echo(f"upserted rule {name!r}")


@rules_app.command("rm")
def rules_rm(name: str) -> None:
    """Delete a rule by name."""
    with _client() as c:
        r = c.delete(f"/api/rules/{name}")
        if r.status_code == 404:
            typer.echo(f"rule {name!r} not found", err=True)
            raise typer.Exit(code=1)
        r.raise_for_status()
        typer.echo(f"deleted rule {name!r}")


@rules_app.command("import")
def rules_import(path: str) -> None:
    """Push every rule from a YAML file to the backend."""
    data = yaml.safe_load(open(path, encoding="utf-8")) or {}
    with _client() as c:
        for raw in data.get("rules", []):
            rule = Rule.model_validate(raw)
            c.post("/api/rules", json=rule.model_dump()).raise_for_status()
            typer.echo(f"imported {rule.name}")


@alerts_app.command("list")
def alerts_list(limit: int = typer.Option(50, "--limit", "-n")) -> None:
    with _client() as c:
        r = c.get("/api/alerts", params={"limit": limit})
        r.raise_for_status()
        for a in r.json():
            typer.echo(
                f"{a['ts']:.0f} [{a['severity']:6}] {a['rule']:30} "
                f"{a['src_ip']} -> {a['dst_ip']} ({a['proto']}) {a['detail']}"
            )


@alerts_app.command("tail")
def alerts_tail() -> None:
    """Follow alerts as they arrive over WebSocket."""

    async def _run() -> None:
        import websockets

        url = DEFAULT_BASE.replace("http", "ws", 1) + "/ws/stream"
        async with websockets.connect(url) as ws:
            async for raw in ws:
                msg = json.loads(raw)
                if msg.get("type") != "alert":
                    continue
                a = msg["data"]
                typer.echo(
                    f"{a['ts']:.0f} [{a['severity']:6}] {a['rule']:30} "
                    f"{a['src_ip']} -> {a['dst_ip']} ({a['proto']}) {a['detail']}"
                )

    asyncio.run(_run())


@app.command("export")
def export_cmd(
    fmt: str = typer.Argument("cef", help="cef|jsonl"),
    output: Optional[str] = typer.Option(None, "--output", "-o"),
    limit: int = typer.Option(1000),
) -> None:
    if fmt not in {"cef", "jsonl"}:
        typer.echo("fmt must be cef or jsonl", err=True)
        raise typer.Exit(code=2)
    with _client() as c:
        r = c.get(f"/api/export/{fmt}", params={"limit": limit})
        r.raise_for_status()
        if output:
            with open(output, "wb") as f:
                f.write(r.content)
            typer.echo(f"wrote {len(r.content)} bytes to {output}")
        else:
            typer.echo(r.text)


if __name__ == "__main__":
    app()
