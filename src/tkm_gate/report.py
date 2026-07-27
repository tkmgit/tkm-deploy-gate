"""Findings, severities and the verdict."""

from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum


class Severity(str, Enum):
    ERROR = "error"
    WARN = "warn"
    OFF = "off"

    @classmethod
    def parse(cls, value: str, where: str) -> "Severity":
        try:
            return cls(str(value).strip().lower())
        except ValueError:
            raise ConfigError(
                "%s: severity must be error, warn or off, got %r" % (where, value)
            ) from None


class ConfigError(Exception):
    """Raised for a malformed gate.toml. Always fatal: a gate that cannot read
    its own configuration must not fall back to passing."""


@dataclass(frozen=True)
class Finding:
    rule: str
    severity: Severity
    detail: str


@dataclass
class Report:
    findings: list[Finding] = field(default_factory=list)
    seen: dict[str, int] = field(default_factory=dict)
    ran: list[str] = field(default_factory=list)
    skipped: dict[str, str] = field(default_factory=dict)

    def add(self, rule: str, severity: Severity, detail: str) -> None:
        self.findings.append(Finding(rule, severity, detail))

    def count(self, rule: str, n: int = 1) -> None:
        self.seen[rule] = self.seen.get(rule, 0) + n

    @property
    def errors(self) -> list[Finding]:
        return [f for f in self.findings if f.severity is Severity.ERROR]

    @property
    def warnings(self) -> list[Finding]:
        return [f for f in self.findings if f.severity is Severity.WARN]
