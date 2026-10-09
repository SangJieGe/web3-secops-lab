"""Week 1 测试：只测当前真实存在的功能。

覆盖：
- 配置读取（有环境变量时读环境变量）
- 配置缺失时回退到默认值
- 结构化日志输出为合法 JSON 且字段正确
- 主流程能正常执行并返回 0
"""

from __future__ import annotations

import json

import pytest

from web3_secops.main import DEFAULTS, load_config, log, main


# ---------------------------------------------------------------------------
# 配置读取
# ---------------------------------------------------------------------------
def test_load_config_uses_defaults_when_env_missing(monkeypatch: pytest.MonkeyPatch) -> None:
    """环境变量缺失时，应回退到 DEFAULTS。"""
    monkeypatch.delenv("APP_NAME", raising=False)
    monkeypatch.delenv("LOG_LEVEL", raising=False)

    config = load_config()

    assert config["APP_NAME"] == DEFAULTS["APP_NAME"]
    assert config["LOG_LEVEL"] == DEFAULTS["LOG_LEVEL"]


def test_load_config_reads_env_when_present(monkeypatch: pytest.MonkeyPatch) -> None:
    """环境变量存在时，应读取环境变量的值。"""
    monkeypatch.setenv("APP_NAME", "my-test-app")
    monkeypatch.setenv("LOG_LEVEL", "DEBUG")

    config = load_config()

    assert config["APP_NAME"] == "my-test-app"
    assert config["LOG_LEVEL"] == "DEBUG"


# ---------------------------------------------------------------------------
# 结构化日志
# ---------------------------------------------------------------------------
def test_log_outputs_valid_json(capsys: pytest.CaptureFixture[str]) -> None:
    """log() 应输出一行合法 JSON，且包含 ts / level / event 及自定义字段。"""
    log("INFO", "unit_test_event", foo="bar")

    captured = capsys.readouterr()
    line = captured.out.strip()
    record = json.loads(line)  # 解析失败会直接让测试报错

    assert record["level"] == "INFO"
    assert record["event"] == "unit_test_event"
    assert record["foo"] == "bar"
    assert "ts" in record


# ---------------------------------------------------------------------------
# 主流程
# ---------------------------------------------------------------------------
def test_main_runs_and_returns_zero(capsys: pytest.CaptureFixture[str]) -> None:
    """主流程应正常执行，返回 0，并输出 startup / config_loaded / shutdown。"""
    exit_code = main()
    captured = capsys.readouterr()

    events = [json.loads(line)["event"] for line in captured.out.strip().splitlines()]

    assert exit_code == 0
    assert "startup" in events
    assert "config_loaded" in events
    assert "shutdown" in events
