"""Tests for detector rules: watched addresses, large transfers, flagged contracts."""

from __future__ import annotations

from web3_secops.block_scanner import NormalizedBlock, NormalizedTx
from web3_secops.detector import (
    Detector,
    DetectorConfig,
    WatchEntry,
    filter_by_severity,
)

WATCHED = "0x1111111111111111111111111111111111111111"
OTHER = "0x9999999999999999999999999999999999999999"
TOKEN = "0x2222222222222222222222222222222222222222"
FLAGGED = "0x0000000000000000000000000000000000000004"


def make_block(txs: list[NormalizedTx], number: int = 16, ts: int = 1_700_000_000):
    return NormalizedBlock(
        number=number, hash="0xabc", parent_hash="0xp", timestamp=ts, transactions=txs
    )


def make_tx(frm: str, to: str | None, wei: int, h: str = "0xtx", idx: int = 0):
    return NormalizedTx(
        hash=h, from_addr=frm, to_addr=to, value_wei=wei, block_number=16, tx_index=idx
    )


def base_config(**kw):
    return DetectorConfig(
        watched={WATCHED: WatchEntry(WATCHED, "Treasury", severity="high")},
        **kw,
    )


def test_outbound_from_watched():
    det = Detector(base_config())
    block = make_block([make_tx(WATCHED, OTHER, 10**18)])
    findings = det.inspect_block(block)
    rules = {f.rule for f in findings}
    assert "watched-outbound" in rules


def test_inbound_to_watched():
    det = Detector(base_config())
    block = make_block([make_tx(OTHER, WATCHED, 10**18)])
    findings = det.inspect_block(block)
    assert any(f.rule == "watched-inbound" for f in findings)


def test_large_transfer_above_threshold():
    det = Detector(base_config(min_notable_value=10.0))
    block = make_block([make_tx(OTHER, OTHER, 50 * 10**18)])
    findings = det.inspect_block(block)
    assert any(f.rule == "large-transfer" for f in findings)


def test_small_transfer_not_flagged():
    det = Detector(base_config(min_notable_value=10.0))
    block = make_block([make_tx(OTHER, OTHER, 10**17)])  # 0.1
    findings = det.inspect_block(block)
    assert not any(f.rule == "large-transfer" for f in findings)


def test_flagged_contract_interaction():
    det = Detector(
        base_config(flagged_contracts={FLAGGED: {"label": "Mixer", "reason": "sanctioned"}})
    )
    block = make_block([make_tx(OTHER, FLAGGED, 0)])
    findings = det.inspect_block(block)
    flagged = [f for f in findings if f.rule == "flagged-interaction"]
    assert flagged and flagged[0].severity == "high"


def test_rapid_drain_detection():
    det = Detector(
        base_config(rapid_drain_count=3, rapid_drain_window_seconds=300)
    )
    ts = 1_700_000_000
    txs = [
        make_tx(WATCHED, OTHER, 10**18, h=f"0x{i}", idx=i) for i in range(3)
    ]
    block = make_block(txs, ts=ts)
    findings = det.inspect_block(block)
    assert any(f.rule == "rapid-drain" for f in findings)


def test_rapid_drain_outside_window_not_flagged():
    det = Detector(base_config(rapid_drain_count=3, rapid_drain_window_seconds=10))
    # Three txs spread far apart in time -> different blocks
    got = []
    for i in range(3):
        b = make_block(
            [make_tx(WATCHED, OTHER, 10**18, h=f"0x{i}")], number=16 + i, ts=1_700_000_000 + i * 100
        )
        got += det.inspect_block(b)
    assert not any(f.rule == "rapid-drain" for f in got)


def test_filter_by_severity():
    det = Detector(base_config())
    block = make_block([make_tx(OTHER, OTHER, 50 * 10**18)])  # medium
    findings = det.inspect_block(block)
    assert filter_by_severity(findings, "high") == []
    assert filter_by_severity(findings, "medium") != []


def test_finding_to_dict_roundtrip():
    det = Detector(base_config())
    block = make_block([make_tx(WATCHED, OTHER, 10**18)])
    f = det.inspect_block(block)[0]
    d = f.to_dict()
    assert d["rule"] and d["severity"] and "context" in d
