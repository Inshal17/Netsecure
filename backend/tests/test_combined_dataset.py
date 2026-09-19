import json
from pathlib import Path

from backend.scripts.build_combined_dataset import build_local_dataset


def test_build_local_dataset_generates_training_records(tmp_path):
    dataset_root = tmp_path / "datasets" / "vendor_configs"
    dataset_root.mkdir(parents=True)
    config_path = dataset_root / "cisco_secure_001.cfg"
    config_path.write_text("hostname EDGE\nip ssh version 2\nlogging enable\n")
    manifest_path = dataset_root / "manifest.json"
    manifest_path.write_text(
        json.dumps(
            [
                {
                    "vendor": "Cisco",
                    "filename": "cisco_secure_001.cfg",
                    "state": "secure",
                    "frameworks": ["CIS Benchmarks"],
                    "source_hint": "https://example.com",
                    "file_path": str(config_path),
                }
            ]
        )
    )

    records = build_local_dataset(dataset_root)

    assert len(records) == 1
    assert records[0]["vendor"] == "Cisco"
    assert records[0]["frameworks"] == ["CIS Benchmarks"]
    assert "instruction" in records[0]
    assert "response" in records[0]
    assert "config_snippet" in records[0]
