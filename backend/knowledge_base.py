"""Offline retrieval layer for curated network-security knowledge."""

from __future__ import annotations

import re
from dataclasses import dataclass
from typing import Any


@dataclass(frozen=True)
class KnowledgeDocument:
    document_id: str
    title: str
    source: str
    source_url: str
    version: str
    frameworks: tuple[str, ...]
    vendors: tuple[str, ...]
    content: str


DOCUMENTS = (
    KnowledgeDocument(
        document_id="baseline-management-access-v1",
        title="Management access baseline",
        source="NetSecureAI curated baseline",
        source_url="https://www.cisecurity.org/controls",
        version="1.0",
        frameworks=("CIS", "NIST", "STIG", "ISO"),
        vendors=("Cisco", "Juniper", "Arista", "Fortinet", "Palo Alto", "HPE Aruba", "Huawei", "Check Point", "SONiC"),
        content=(
            "Disable Telnet and other clear-text administrative protocols. Prefer SSH version 2 "
            "for remote administration. Administrative access should use centralized authentication "
            "where supported and should be protected with session timeout controls."
        ),
    ),
    KnowledgeDocument(
        document_id="audit-logging-time-v1",
        title="Audit logging and trusted time",
        source="NetSecureAI curated baseline",
        source_url="https://csrc.nist.gov/publications/detail/sp/800-53/rev-5/final",
        version="1.0",
        frameworks=("CIS", "NIST", "STIG", "ISO"),
        vendors=("Cisco", "Juniper", "Arista", "Fortinet", "Palo Alto", "HPE Aruba", "Huawei", "Check Point", "SONiC"),
        content=(
            "Network devices should generate administrative and security audit logs and forward them "
            "to an approved central collector. Configure a trusted NTP source so event timestamps can "
            "be correlated during incident investigation."
        ),
    ),
    KnowledgeDocument(
        document_id="legacy-services-hardening-v1",
        title="Legacy services and control-plane hardening",
        source="DISA network device hardening crosswalk",
        source_url="https://public.cyber.mil/stigs/",
        version="2024-crosswalk",
        frameworks=("STIG", "NIST", "ISO"),
        vendors=("Cisco", "Juniper", "Fortinet", "Palo Alto", "Huawei", "Check Point"),
        content=(
            "Disable unnecessary legacy services such as FTP, reverse Telnet, insecure HTTP management, "
            "and IP source routing. Limit administrative connection attempts and SSH rate where the "
            "platform provides those controls."
        ),
    ),
)


def _tokens(value: str) -> set[str]:
    return {
        token
        for token in re.findall(r"[a-z0-9][a-z0-9_-]+", value.lower())
        if len(token) > 2
    }


def search_knowledge(
    query: str,
    *,
    vendor: str | None = None,
    framework: str | None = None,
    limit: int = 3,
) -> list[dict[str, Any]]:
    query_tokens = _tokens(query)
    normalized_vendor = (vendor or "").lower()
    normalized_framework = (framework or "").lower()
    ranked: list[tuple[int, KnowledgeDocument]] = []

    for document in DOCUMENTS:
        content_tokens = _tokens(
            f"{document.title} {document.content} {' '.join(document.vendors)}"
        )
        score = len(query_tokens & content_tokens)
        if normalized_vendor and any(normalized_vendor == item.lower() for item in document.vendors):
            score += 3
        if normalized_framework and normalized_framework in {item.lower() for item in document.frameworks}:
            score += 2
        if score:
            ranked.append((score, document))

    ranked.sort(key=lambda item: (-item[0], item[1].document_id))
    return [
        {
            "documentId": document.document_id,
            "title": document.title,
            "source": document.source,
            "sourceUrl": document.source_url,
            "version": document.version,
            "frameworks": document.frameworks,
            "vendors": document.vendors,
            "content": document.content,
            "score": score,
        }
        for score, document in ranked[: max(1, min(limit, 10))]
    ]
