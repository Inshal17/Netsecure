from typing import Any

import requests

from .config import FABRIC_GATEWAY_URL
from .hashing import sha256_hash


def anchor_record(
    record_id: str,
    record_type: str,
    analysis_id: str,
    payload: Any,
    device_id: str | None = None,
    vendor: str | None = None,
    framework: str | None = None,
    actor: str = "system",
    previous_hash: str = "",
) -> dict:
    """Create a tamper-evident hash and send it to the Fabric Gateway."""

    blockchain_payload = {
        "record_id": record_id,
        "record_type": record_type,
        "analysis_id": analysis_id,
        "device_id": device_id,
        "vendor": vendor,
        "framework": framework,
        "payload": payload,
        "actor": actor,
        "previous_hash": previous_hash,
    }

    record_hash = sha256_hash(blockchain_payload)

    response = requests.post(
        f"{FABRIC_GATEWAY_URL}/anchor",
        json={
            "record_id": record_id,
            "record_type": record_type,
            "analysis_id": analysis_id,
            "device_id": device_id,
            "vendor": vendor,
            "framework": framework,
            "hash": record_hash,
            "hash_algorithm": "SHA-256",
            "actor": actor,
            "previous_hash": previous_hash,
        },
        timeout=30,
    )

    response.raise_for_status()

    result = response.json()

    return {
        "record_id": record_id,
        "analysis_id": analysis_id,
        "hash": record_hash,
        "hash_algorithm": "SHA-256",
        "previous_hash": previous_hash,
        "transaction_id": result.get("transaction_id", ""),
        "status": result.get("status", "anchored"),
    }


def verify_record(
    record_id: str,
    record_type: str,
    analysis_id: str,
    payload: Any,
    device_id: str | None = None,
    vendor: str | None = None,
    framework: str | None = None,
    actor: str = "system",
    previous_hash: str = "",
) -> dict:
    """Recalculate the hash and verify it against the blockchain record."""

    blockchain_payload = {
        "record_id": record_id,
        "record_type": record_type,
        "analysis_id": analysis_id,
        "device_id": device_id,
        "vendor": vendor,
        "framework": framework,
        "payload": payload,
        "actor": actor,
        "previous_hash": previous_hash,
    }

    current_hash = sha256_hash(blockchain_payload)

    response = requests.post(
        f"{FABRIC_GATEWAY_URL}/verify",
        json={
            "record_id": record_id,
            "hash": current_hash,
        },
        timeout=30,
    )

    response.raise_for_status()

    result = response.json()

    blockchain_hash = result.get("blockchain_hash", "")

    return {
        "record_id": record_id,
        "supplied_hash": current_hash,
        "blockchain_hash": blockchain_hash,
        "verified": current_hash == blockchain_hash,
        "status": result.get("status", "verified"),
    }