import json
from datetime import datetime, timezone
from email_intel.plocamium_bridge import PlocamiumBridge
from email_intel.models import StackChange, ChangeClassification, OrgInfraSignal


def _make_signal() -> OrgInfraSignal:
    change = StackChange(id=42, domain="gs.com", timestamp=datetime(2026, 3, 19, tzinfo=timezone.utc),
        field="dmarc_policy", old_value="quarantine", new_value="reject")
    cls = ChangeClassification(change=change, signal="positive", confidence=1.0,
        reasoning="DMARC hardened", category="security")
    return OrgInfraSignal(signal_id=42, domain="gs.com", entity_id="ent_1",
        entity_name="Goldman Sachs", sector="Financial Services",
        change=change, classification=cls, timestamp=datetime(2026, 3, 19, tzinfo=timezone.utc))


def test_buffer_and_flush_local(tmp_path):
    output_path = str(tmp_path / "signals.jsonl")
    bridge = PlocamiumBridge(enabled=True, output="local", local_path=output_path)
    bridge.buffer(_make_signal())
    bridge.buffer(_make_signal())
    assert bridge.pending_count == 2
    bridge.flush()
    assert bridge.pending_count == 0
    with open(output_path) as f:
        lines = f.readlines()
    assert len(lines) == 2
    data = json.loads(lines[0])
    assert data["domain"] == "gs.com"
    assert data["signal"] == "positive"
    assert data["signal_id"] == 42


def test_disabled_bridge_no_output(tmp_path):
    output_path = str(tmp_path / "signals.jsonl")
    bridge = PlocamiumBridge(enabled=False, output="local", local_path=output_path)
    bridge.buffer(_make_signal())
    bridge.flush()
    import os
    assert not os.path.exists(output_path)


def test_flush_empty_buffer(tmp_path):
    output_path = str(tmp_path / "signals.jsonl")
    bridge = PlocamiumBridge(enabled=True, output="local", local_path=output_path)
    bridge.flush()
    import os
    assert not os.path.exists(output_path)
