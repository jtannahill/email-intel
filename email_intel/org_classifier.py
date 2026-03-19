from __future__ import annotations
from email_intel.models import ChangeClassification, StackChange

TRANSITION_RULES: list[tuple[str, str, str, str, str, str]] = [
    ("dmarc_policy", "none", "quarantine", "positive", "security", "DMARC strengthened to quarantine"),
    ("dmarc_policy", "none", "reject", "positive", "security", "DMARC strengthened to reject"),
    ("dmarc_policy", "quarantine", "reject", "positive", "security", "DMARC hardened to reject"),
    ("dmarc_policy", "reject", "quarantine", "negative", "security", "DMARC weakened"),
    ("dmarc_policy", "reject", "none", "negative", "security", "DMARC removed"),
    ("dmarc_policy", "quarantine", "none", "negative", "security", "DMARC removed"),
    ("tls_version", "TLS1_0", "TLS1_2", "positive", "modernization", "TLS upgraded"),
    ("tls_version", "TLS1_0", "TLS1_3", "positive", "modernization", "TLS upgraded to 1.3"),
    ("tls_version", "TLS1_2", "TLS1_3", "positive", "modernization", "TLS upgraded to 1.3"),
    ("tls_version", "TLS1_3", "TLS1_2", "negative", "security", "TLS downgraded"),
    ("tls_version", "TLS1_2", "TLS1_0", "negative", "security", "TLS downgraded"),
    ("email_platform", "on-prem-exchange", "m365", "positive", "migration", "Cloud migration to M365"),
    ("email_platform", "on-prem-exchange", "google-workspace", "positive", "migration", "Cloud migration to Google"),
    ("email_platform", "m365", "on-prem-exchange", "negative", "cost-cut", "Cloud to on-prem regression"),
]

_RULE_MAP: dict[tuple[str, str | None, str | None], tuple[str, str, str]] = {
    (field, old, new): (signal, category, reasoning)
    for field, old, new, signal, category, reasoning in TRANSITION_RULES
}


def classify_change(change: StackChange) -> ChangeClassification:
    key = (change.field, change.old_value, change.new_value)
    if key in _RULE_MAP:
        signal, category, reasoning = _RULE_MAP[key]
        return ChangeClassification(change=change, signal=signal, confidence=1.0, reasoning=reasoning, category=category)

    if change.field == "security_gateway":
        if change.old_value is None and change.new_value is not None:
            return ChangeClassification(change=change, signal="positive", confidence=0.9,
                reasoning=f"Security gateway added: {change.new_value}", category="security")
        if change.old_value is not None and change.new_value is None:
            return ChangeClassification(change=change, signal="negative", confidence=0.9,
                reasoning=f"Security gateway removed: {change.old_value}", category="cost-cut")
        if change.old_value and change.new_value:
            return ChangeClassification(change=change, signal="neutral", confidence=0.7,
                reasoning=f"Security gateway changed: {change.old_value} → {change.new_value}", category="migration")

    if change.field == "dlp_system":
        if change.old_value is None and change.new_value is not None:
            return ChangeClassification(change=change, signal="positive", confidence=0.9,
                reasoning=f"DLP system added: {change.new_value}", category="security")

    return ChangeClassification(change=change, signal="neutral", confidence=0.5,
        reasoning=f"{change.field} changed: {change.old_value} → {change.new_value}", category="maintenance")
