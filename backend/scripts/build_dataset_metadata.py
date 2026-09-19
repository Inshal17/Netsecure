#!/usr/bin/env python3
import json
from pathlib import Path

root = Path(__file__).resolve().parents[2] / 'data' / 'datasets' / 'vendor_configs'
manifest = json.loads((root / 'manifest.json').read_text())
records = []
for item in manifest:
    path = root / item['filename']
    content = path.read_text(errors='replace')
    records.append({
        'vendor': item['vendor'],
        'filename': item['filename'],
        'state': item['state'],
        'frameworks': ';'.join(item['frameworks']),
        'source_hint': item['source_hint'],
        'config_path': item['file_path'],
        'content_preview': content[:400].replace('\n', ' '),
    })

csv_lines = ['vendor,filename,state,frameworks,source_hint,config_path,content_preview']
for rec in records:
    preview = rec['content_preview'].replace('"', '""')
    csv_lines.append(
        f'"{rec["vendor"]}","{rec["filename"]}","{rec["state"]}","{rec["frameworks"]}","{rec["source_hint"]}","{rec["config_path"]}","{preview}"'
    )
(root / 'dataset_metadata.csv').write_text('\n'.join(csv_lines) + '\n')

summary = {}
for rec in records:
    vendor = summary.setdefault(rec['vendor'], {'total': 0, 'states': {}})
    vendor['total'] += 1
    vendor['states'][rec['state']] = vendor['states'].get(rec['state'], 0) + 1
(root / 'dataset_summary.json').write_text(json.dumps(summary, indent=2))

print(f'metadata_rows={len(records)}')
print(f'metadata_exists={(root / "dataset_metadata.csv").exists()}')
print(f'summary_exists={(root / "dataset_summary.json").exists()}')
print(f'vendors={sorted(summary)}')
