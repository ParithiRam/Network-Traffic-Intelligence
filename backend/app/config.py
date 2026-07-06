from __future__ import annotations

import os
from dataclasses import dataclass


@dataclass(frozen=True)
class Settings:
    db_url: str = os.getenv("NTI_DB_URL", "sqlite+aiosqlite:///./nti.db")
    rules_path: str = os.getenv("NTI_RULES_PATH", "./rules.yaml")
    pcap_path: str | None = os.getenv("NTI_PCAP_PATH") or None
    simulate: bool = os.getenv("NTI_SIMULATE", "1") == "1"
    sim_pps: int = int(os.getenv("NTI_SIM_PPS", "40"))
    queue_size: int = int(os.getenv("NTI_QUEUE_SIZE", "10000"))
    metrics_window_s: int = int(os.getenv("NTI_METRICS_WINDOW_S", "120"))
    portscan_distinct_ports: int = int(os.getenv("NTI_PORTSCAN_PORTS", "20"))
    portscan_window_s: int = int(os.getenv("NTI_PORTSCAN_WINDOW_S", "10"))
    spike_zscore: float = float(os.getenv("NTI_SPIKE_Z", "3.0"))
    cors_origin: str = os.getenv("NTI_CORS_ORIGIN", "*")


settings = Settings()
