"""Atomic, repeatable imports of the repository's synthetic corpus."""
import hashlib
import json
from pathlib import Path

from src.app.database import transaction
from src.app.repositories.demo_repo import batch_finding_ids
from src.app.services.normalizer import normalizer_service

DATA_DIR = Path(__file__).resolve().parents[3] / 'data'
DATASETS = {
    'burp-sqli': ('burp_sqli.sarif', 'burp', 'SQL injection', 25),
    'nessus-sqli': ('nessus_sqli.json', 'nessus', 'SQL injection', 25),
    'burp-xss': ('burp_xss.sarif', 'burp', 'Cross-site scripting', 20),
    'zap-xss': ('zap_xss.json', 'zap', 'Cross-site scripting', 20),
    'burp-ssrf': ('burp_ssrf.json', 'burp', 'Server-side request forgery', 10),
    'nessus-ssrf': ('nessus_ssrf.sarif', 'nessus', 'Server-side request forgery', 10),
    'workflow-sample': ('sample_workflow_upload.json', 'sample', 'Mixed workflow sample', 6),
}


def load_dataset(dataset_id: str) -> dict:
    if dataset_id not in DATASETS:
        raise LookupError(f"Synthetic dataset '{dataset_id}' not found.")
    filename, scanner, _, expected_count = DATASETS[dataset_id]
    source = (DATA_DIR / filename).read_bytes()
    payload = json.loads(source)
    is_sarif = isinstance(payload, dict) and 'runs' in payload
    records = [record for run in payload['runs'] for record in run.get('results', [])] if is_sarif else payload
    if not isinstance(records, list) or len(records) != expected_count:
        raise ValueError(f'Unexpected record count or format in {filename}.')
    digest = hashlib.sha256(b'demo-loader-v2\0' + dataset_id.encode() + b'\0' + source).hexdigest()
    batch_id = f'demo-{digest}'
    with transaction():
        previous = batch_finding_ids(batch_id)
        normalized = warnings = 0
        if previous and len(previous) != len(records):
            raise ValueError('Incomplete demo batch requires reconciliation.')
        if not previous:
            for record in records:
                finding = normalizer_service.normalize_record(
                    record, scanner, batch_id, source_file=filename,
                    parser_key='sarif' if is_sarif else scanner,
                )
                if finding.quality.normalization_status == 'rejected':
                    raise ValueError('Demo fixture was rejected during normalization.')
                if finding.quality.normalization_status == 'normalized':
                    normalized += 1
                else:
                    warnings += 1
        return dict(batch_id=batch_id, source_scanner=scanner, total_received=len(records),
                    normalized=normalized, normalized_with_warnings=warnings, rejected=0,
                    rejected_details=[], status='completed', next_stage='multi_view_extraction',
                    already_loaded=len(previous), finding_ids=previous or batch_finding_ids(batch_id))
