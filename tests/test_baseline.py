from fastapi.testclient import TestClient

from src.app.main import app
from src.app.repositories.findings_repo import repo


def test_startup_and_ingestion_persist_across_clients():
    assert repo.count_normalized_findings() == 0
    with TestClient(app) as client:
        health = client.get('/health')
        assert health.status_code == 200
        assert health.json()['tables_initialized'] == 14
        response = client.post('/api/v1/findings', json={
            'source_scanner': 'burp', 'findings': [
                {'name': 'SQL Injection', 'host': 'app.example.test', 'path': '/login'}]})
        assert response.status_code == 201
        assert response.json()['rejected'] == 0
        assert client.get('/docs').status_code == 200
        page = client.get('/').text
        assert 'Vulnerability Triage Lab' in page
        assert 'Synthetic scanner corpus' in page
        assert '/static/dashboard.js' in page
        assert client.get('/static/dashboard.css').status_code == 200
        assert client.get('/static/dashboard.js').status_code == 200
    with TestClient(app) as client:
        assert client.get('/api/v1/findings').json()['total'] == 1


def test_empty_and_malformed_ingestion():
    with TestClient(app) as client:
        assert client.post('/api/v1/findings', json={
            'source_scanner': 'burp', 'findings': []}).status_code == 400
        assert client.post('/api/v1/findings/upload', data={'source_scanner': 'burp'},
                           files={'file': ('broken.json', b'{')}).status_code == 400
    assert repo.count_normalized_findings() == 0


def test_existing_database_migration_preserves_records(tmp_path, monkeypatch):
    import sqlite3
    from src.app import database
    from src.app.config import settings

    path = tmp_path / 'legacy.db'
    # The original DDL deliberately remains unchanged; additive migrations run afterward.
    with sqlite3.connect(path) as db:
        for statement in database._TABLES:
            db.execute(statement)
        db.execute('''INSERT INTO audit_events (event_id,entity_type,entity_id,action,
                      occurred_at,created_at) VALUES ('old','finding','f1','existing','now','now')''')
    monkeypatch.setattr(settings, 'database_path', str(path))
    database.init_db()
    database.init_db()
    with database.get_db() as db:
        assert db.execute('SELECT event_id FROM audit_events').fetchone()[0] == 'old'
        for table, column in [('canonical_issues', 'active'), ('cases', 'stale'),
                              ('threat_intelligence', 'source_fingerprint')]:
            assert column in {row['name'] for row in db.execute(f'PRAGMA table_info({table})')}
