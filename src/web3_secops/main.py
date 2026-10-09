"""Web3 SecOps Lab — Week 1 程序入口。

第一周的目标很小，只有三件事：

1. 程序能启动。
2. 能读取配置文件（环境变量 / .env）。
3. 能输出结构化日志（每行一个 JSON）。

链上数据读取（Ethereum JSON-RPC）属于 Week 2，暂不集成到主程序。

运行方式：

    python -m web3_secops.main
"""

from __future__ import annotations

import json
import os
import sys
from datetime import UTC, datetime
from typing import Any

from dotenv import load_dotenv


# ---------------------------------------------------------------------------
# 1. 结构化日志
# ---------------------------------------------------------------------------
def log(level: str, event: str, **fields: Any) -> None:
    """输出一行 JSON 结构化日志到 stdout。

    每行是一个独立的 JSON 对象（JSON Lines 格式）。
    这样做的好处是：日志既能给人看，也能被程序解析，
    以后要接 Wazuh / Filebeat 之类的采集器时会很方便。
    """
    record = {
        "ts": datetime.now(UTC).isoformat(),
        "level": level,
        "event": event,
        **fields,
    }
    print(json.dumps(record, ensure_ascii=False, default=str), flush=True)


# ---------------------------------------------------------------------------
# 2. 读取配置
# ---------------------------------------------------------------------------
# 第一周只有这几个配置项，都是当前程序真正会用到的。
DEFAULTS: dict[str, str] = {
    "APP_NAME": "web3-secops-lab",
    "LOG_LEVEL": "INFO",
}


def load_config() -> dict[str, Any]:
    """从环境变量（含 .env 文件）读取配置，缺失时回退到 DEFAULTS。

    优先级：真实环境变量 > .env 文件 > 代码内 DEFAULTS。

    load_dotenv() 默认不会覆盖已经存在的环境变量，
    所以这个优先级顺序是天然成立的。
    """
    load_dotenv()  # 把 .env 里的键值读进 os.environ

    config: dict[str, Any] = {}
    for key, default in DEFAULTS.items():
        config[key] = os.getenv(key, default)

    return config


# ---------------------------------------------------------------------------
# 3. 主流程
# ---------------------------------------------------------------------------
def main() -> int:
    """程序主入口：启动 → 读配置 → 打日志 → 退出。"""
    log("INFO", "startup", app="web3-secops-lab")

    try:
        config = load_config()
    except Exception as exc:  # noqa: BLE001 — 配置读不出来就直接报错退出
        log("ERROR", "config_load_failed", error=str(exc))
        return 1

    log(
        "INFO",
        "config_loaded",
        app_name=config["APP_NAME"],
        log_level=config["LOG_LEVEL"],
    )

    log("INFO", "shutdown", status="ok")
    return 0


if __name__ == "__main__":
    sys.exit(main())
