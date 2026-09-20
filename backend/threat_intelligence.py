from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from typing import Any


@dataclass
class ThreatIntelEvidence:
    matched: bool
    provider: str
    indicators: list[dict[str, Any]] = field(default_factory=list)


class ThreatIntelligenceProvider(ABC):
    @abstractmethod
    def lookup_url(self, url: str) -> ThreatIntelEvidence:
        """Return threat-intelligence evidence for a URL."""


class LocalThreatIntelligenceProvider(ThreatIntelligenceProvider):
    def lookup_url(self, url: str) -> ThreatIntelEvidence:
        return ThreatIntelEvidence(
            matched=False,
            provider="local",
            indicators=[],
        )


_DEFAULT_PROVIDER = LocalThreatIntelligenceProvider()


def lookup_url_threat_intelligence(
    url: str,
    provider: ThreatIntelligenceProvider | None = None,
) -> ThreatIntelEvidence:
    selected_provider = provider or _DEFAULT_PROVIDER
    return selected_provider.lookup_url(url)
