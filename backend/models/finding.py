from dataclasses import dataclass, field
from typing import List, Optional


@dataclass
class Finding:
    """Represents a KernelShield security finding."""

    finding_id: str

    category: str

    title: str

    severity: str

    description: str

    evidence: List[str] = field(default_factory=list)

    impact: Optional[str] = None

    recommendation: Optional[str] = None

    confidence: str = "medium"

    references: List[str] = field(default_factory=list)

    def to_dict(self):
        return {
            "finding_id": self.finding_id,
            "category": self.category,
            "title": self.title,
            "severity": self.severity,
            "description": self.description,
            "evidence": self.evidence,
            "impact": self.impact,
            "recommendation": self.recommendation,
            "confidence": self.confidence,
            "references": self.references,
        }
