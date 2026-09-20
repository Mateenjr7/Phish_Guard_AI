from dataclasses import fields

from backend.threat_intelligence import (
    LocalThreatIntelligenceProvider,
    ThreatIntelEvidence,
    ThreatIntelligenceProvider,
    lookup_url_threat_intelligence,
)


def test_local_provider_returns_no_match():
    evidence = LocalThreatIntelligenceProvider().lookup_url(
        "https://github.com"
    )

    assert evidence.matched is False
    assert evidence.provider == "local"
    assert evidence.indicators == []


def test_threat_intel_evidence_has_expected_structure():
    evidence = ThreatIntelEvidence(
        matched=False,
        provider="local",
    )

    assert {field.name for field in fields(ThreatIntelEvidence)} == {
        "matched",
        "provider",
        "indicators",
    }
    assert isinstance(evidence.indicators, list)
    assert isinstance(LocalThreatIntelligenceProvider(), ThreatIntelligenceProvider)


def test_lookup_helper_uses_injected_provider():
    class TestProvider(ThreatIntelligenceProvider):
        def lookup_url(self, url: str) -> ThreatIntelEvidence:
            return ThreatIntelEvidence(
                matched=True,
                provider="test",
                indicators=[
                    {
                        "type": "known_malicious_url",
                        "severity": "critical",
                        "message": "URL matched test intelligence.",
                    }
                ],
            )

    evidence = lookup_url_threat_intelligence(
        "https://malicious.example",
        provider=TestProvider(),
    )

    assert evidence.matched is True
    assert evidence.provider == "test"
    assert evidence.indicators[0]["type"] == "known_malicious_url"
