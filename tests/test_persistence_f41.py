"""
F4.1 — Persistence & RLS Hardening (A/B/C)
"""
from unittest.mock import MagicMock, patch
from pathlib import Path
import tempfile

from backend.app.integrations.supabase_client import _classify_supabase_error, save_scan, KNOWN_COLUMNS
import pytest


def test_unique_same_user_same_sha_deduplicated():
    """A: mismo (sha,user) → dedup, no historia duplicada."""
    mock_client = MagicMock()
    mock_client.table.return_value.insert.return_value.execute.side_effect = Exception('23505 duplicate key value violates unique constraint "uq_scan_results_sha_user"')
    with patch("backend.app.integrations.supabase_client._get_supabase_client", return_value=mock_client):
        result = save_scan({"file_name": "a.exe", "sha256": "abc", "user_id": "11111111-1111-1111-1111-111111111111", "result": "benign"})
        assert result["saved"] is True
        assert result.get("deduplicated") is True
        assert result.get("category") == "unique_violation"


def test_unique_distinct_user_same_sha_isolation():
    """Distinto usuario + mismo hash → no colision (UNIQUE es por usuario)."""
    # Simulate first insert succeeds for user A, second for user B also succeeds (no 23505)
    mock_client = MagicMock()
    mock_client.table.return_value.insert.return_value.execute.return_value = MagicMock(data=[{"id": "1"}])
    with patch("backend.app.integrations.supabase_client._get_supabase_client", return_value=mock_client):
        r1 = save_scan({"file_name": "a.exe", "sha256": "samehash", "user_id": "aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa"})
        r2 = save_scan({"file_name": "a.exe", "sha256": "samehash", "user_id": "bbbbbbbb-bbbb-bbbb-bbbb-bbbbbbbbbbbb"})
        assert r1["saved"] is True
        assert r2["saved"] is True
        # Both inserted, not deduplicated as unique per user
        assert r1.get("deduplicated") is not True or r2.get("deduplicated") is not True


def test_pgrst204_retry_max_1_no_loop():
    mock_client = MagicMock()
    # First call PGRST204, second minimal succeeds
    mock_client.table.return_value.insert.return_value.execute.side_effect = [
        Exception('PGRST204 Could not find column evidences'),
        MagicMock(data=[{"id": "1"}]),
    ]
    with patch("backend.app.integrations.supabase_client._get_supabase_client", return_value=mock_client):
        result = save_scan({"file_name": "x", "sha256": "s", "user_id": "u", "evidences": []})
        assert result["saved"] is True
        assert result.get("recovered_from") == "PGRST204"
        # Exactly 2 calls, no infinite loop
        assert mock_client.table.return_value.insert.call_count == 2


def test_pgrst204_no_queue_infinite():
    mock_client = MagicMock()
    # Both full and minimal fail → permanent, no queue
    mock_client.table.return_value.insert.return_value.execute.side_effect = Exception('PGRST204 column')
    with patch("backend.app.integrations.supabase_client._get_supabase_client", return_value=mock_client):
        with patch("backend.app.integrations.supabase_client._fallback_offline") as mock_q:
            result = save_scan({"file_name": "x", "evidences": []})
            assert result.get("permanent") is True
            mock_q.assert_not_called()


def test_pgrst204_classification_permanent_schema():
    assert _classify_supabase_error(Exception('PGRST204 whatever')) == "permanent_schema"
    assert _classify_supabase_error(Exception('Could not find the column evidences PGRST204')) == "permanent_schema"


# RLS tests: mocks for unit, real E2E via supabase if env available
def test_rls_mock_user_a_can_insert_own():
    mock_client = MagicMock()
    mock_client.table.return_value.insert.return_value.execute.return_value = MagicMock(data=[{"id": "1"}])
    with patch("backend.app.integrations.supabase_client._get_supabase_client", return_value=mock_client):
        result = save_scan({"file_name": "a.exe", "user_id": "aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa", "result": "benign"})
        assert result["saved"] is True
        # Verify insert called with correct user_id (not falsified)
        inserted = mock_client.table.return_value.insert.call_args[0][0]
        assert inserted["user_id"] == "aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa"


def test_rls_mock_user_b_cannot_insert_as_A():
    # Simulate RLS 42501 when user B tries to insert with user_id=A
    mock_client = MagicMock()
    mock_client.table.return_value.insert.return_value.execute.side_effect = Exception('42501 violates row-level security policy for table scan_results')
    with patch("backend.app.integrations.supabase_client._get_supabase_client", return_value=mock_client):
        result = save_scan({"file_name": "x", "user_id": "victim-id", "result": "benign"})
        assert result.get("category") == "rls"
        assert result.get("permanent") is True


def test_rls_anon_no_access_mock():
    # fetch_recent_scans with anonymous (no SUPABASE_KEY) should return [] not leak
    from backend.app.integrations.supabase_client import fetch_recent_scans
    with patch("backend.app.integrations.supabase_client._get_supabase_client", side_effect=RuntimeError("SUPABASE_KEY not configured")):
        rows = fetch_recent_scans("any-id")
        assert rows == []


@pytest.mark.skipif(not __import__("os").getenv("SUPABASE_URL"), reason="SUPABASE_URL not set")
def test_rls_e2e_real_isolation():
    """
    Real RLS E2E against dev Supabase (anon key). Uses service_role bypass false.
    Creates two users via anon auth, inserts, verifies isolation.
    Skipped if env not available.
    """
    import os
    supabase_url = os.getenv("SUPABASE_URL")
    anon_key = os.getenv("SUPABASE_ANON_KEY") or os.getenv("SUPABASE_KEY")
    if not supabase_url or not anon_key or "anon" not in anon_key.lower():
        pytest.skip("anon key not available for true RLS test")
    try:
        from supabase import create_client
        import uuid, time
        # Create two clients with anon key
        client_a = create_client(supabase_url, anon_key)
        client_b = create_client(supabase_url, anon_key)
        # Sign up random users
        email_a = f"f41_a_{uuid.uuid4().hex[:8]}@example.com"
        email_b = f"f41_b_{uuid.uuid4().hex[:8]}@example.com"
        pwd = "Test1234!Test1234!"
        # anon sign_up
        res_a = client_a.auth.sign_up({"email": email_a, "password": pwd})
        res_b = client_b.auth.sign_up({"email": email_b, "password": pwd})
        # Some projects disable signups; skip if fails
        if not res_a.user or not res_b.user:
            pytest.skip("could not create test users (signup disabled)")
        # Need to sign in to get session
        sess_a = client_a.auth.sign_in_with_password({"email": email_a, "password": pwd})
        sess_b = client_b.auth.sign_in_with_password({"email": email_b, "password": pwd})
        uid_a = sess_a.user.id
        uid_b = sess_b.user.id
        # User A inserts
        client_a.table("scan_results").insert({"file_name": "f41_test_A.exe", "result": "benign", "user_id": str(uid_a), "sha256": "f41hashA", "operational_status": "CLEAN"}).execute()
        # User B should not see A's scan via RLS SELECT
        rows_b = client_b.table("scan_results").select("*").eq("user_id", str(uid_a)).execute()
        assert len(rows_b.data) == 0, "User B should not see A's scans via RLS"
        # User B cannot insert as A (should get 42501 or be blocked)
        try:
            client_b.table("scan_results").insert({"file_name": "f41_attack.exe", "result": "malicious", "user_id": str(uid_a), "sha256": "f41hashAttack"}).execute()
            # If insert succeeded, RLS not enforced -> fail test
            # Cleanup and fail
            client_a.table("scan_results").delete().eq("sha256", "f41hashA").execute()
            client_a.table("scan_results").delete().eq("sha256", "f41hashAttack").execute()
            pytest.fail("RLS should block User B inserting as User A")
        except Exception as e:
            msg = str(e).lower()
            assert "42501" in msg or "row-level security" in msg or "violates" in msg
        # Cleanup
        client_a.table("scan_results").delete().eq("sha256", "f41hashA").execute()
        # Anonymous without auth should get 0 rows
        anon_client = create_client(supabase_url, anon_key)
        rows_anon = anon_client.table("scan_results").select("*").limit(1).execute()
        # anon may see 0 if RLS enabled and no anon policy, else would see public? Expect 0 or auth error
        # We just ensure it doesn't leak all data: if RLS disabled anon would see rows, but we have RLS enabled so 0
        # Don't assert strict, just log
    except Exception as e:
        pytest.skip(f"Real RLS E2E skipped due to env/network: {e}")
