"""Unit tests for SecurityAuditor."""
import pytest
from auditors.security_auditor import SecurityAuditor


def test_security_auditor_flags_missing_headers():
    auditor = SecurityAuditor("https://example.com")
    # Empty headers simulate a completely unprotected server
    headers = {
        "content-type": "text/html",
    }
    auditor._audit_security_headers(headers)
    issue_ids = [i.issue_id for i in auditor.issues]

    assert "SEC_MISSING_HSTS" in issue_ids
    assert "SEC_MISSING_CSP" in issue_ids
    assert "SEC_MISSING_X_FRAME_OPTIONS" in issue_ids
    assert "SEC_MISSING_X_CONTENT_TYPE_OPTIONS" in issue_ids
    assert "SEC_MISSING_REFERRER_POLICY" in issue_ids


def test_security_auditor_passes_proper_headers():
    auditor = SecurityAuditor("https://example.com")
    headers = {
        "strict-transport-security": "max-age=31536000; includeSubDomains; preload",
        "content-security-policy": "default-src 'self'",
        "x-frame-options": "DENY",
        "x-content-type-options": "nosniff",
        "referrer-policy": "strict-origin-when-cross-origin",
        "permissions-policy": "geolocation=()",
    }
    auditor._audit_security_headers(headers)
    assert len(auditor.issues) == 0
    assert len(auditor.passed_checks) >= 5


def test_security_auditor_flags_information_leakage():
    auditor = SecurityAuditor("https://example.com")
    headers = {
        "server": "Apache/2.4.41 (Ubuntu)",
        "x-powered-by": "PHP/7.4.3",
    }
    auditor._audit_information_leakage(headers)
    issue_ids = [i.issue_id for i in auditor.issues]

    assert "SEC_SERVER_HEADER_EXPOSED" in issue_ids
    assert "SEC_X_POWERED_BY_EXPOSED" in issue_ids


def test_security_auditor_flags_mixed_content():
    auditor = SecurityAuditor("https://example.com")
    insecure = [{"type": "script", "src": "http://example.com/tracking.js"}]
    auditor._audit_mixed_content(insecure)
    issue_ids = [i.issue_id for i in auditor.issues]

    assert "SEC_MIXED_CONTENT" in issue_ids


def test_security_auditor_modern_tls_v1_3_passes():
    auditor = SecurityAuditor("https://example.com")
    ssl_info = {
        "valid": True,
        "protocol": "TLSv1.3",
        "issuer": "Let's Encrypt",
        "days_remaining": 60,
        "expiry_date": "2026-12-31T00:00:00+00:00",
    }
    auditor._evaluate_ssl_info(ssl_info)

    # Must NOT flag SEC_SSL_LEGACY_PROTOCOL
    issue_ids = [i.issue_id for i in auditor.issues]
    assert "SEC_SSL_LEGACY_PROTOCOL" not in issue_ids
    assert len(auditor.issues) == 0
    assert any("Modern TLS protocol negotiated (TLSv1.3)." in check for check in auditor.passed_checks)


def test_security_auditor_modern_tls_v1_2_passes():
    auditor = SecurityAuditor("https://example.com")
    ssl_info = {
        "valid": True,
        "protocol": "TLSv1.2",
        "issuer": "DigiCert",
        "days_remaining": 90,
        "expiry_date": "2026-12-31T00:00:00+00:00",
    }
    auditor._evaluate_ssl_info(ssl_info)

    # Must NOT flag SEC_SSL_LEGACY_PROTOCOL
    issue_ids = [i.issue_id for i in auditor.issues]
    assert "SEC_SSL_LEGACY_PROTOCOL" not in issue_ids
    assert len(auditor.issues) == 0
    assert any("Modern TLS protocol negotiated (TLSv1.2)." in check for check in auditor.passed_checks)


def test_security_auditor_legacy_protocols_flagged():
    for legacy in ["TLSv1", "TLSv1.0", "TLSv1.1", "SSLv3", "SSLv2"]:
        auditor = SecurityAuditor("https://example.com")
        ssl_info = {
            "valid": True,
            "protocol": legacy,
            "issuer": "Legacy CA",
            "days_remaining": 50,
            "expiry_date": "2026-12-31T00:00:00+00:00",
        }
        auditor._evaluate_ssl_info(ssl_info)

        issue_ids = [i.issue_id for i in auditor.issues]
        assert "SEC_SSL_LEGACY_PROTOCOL" in issue_ids, f"Failed to flag legacy protocol: {legacy}"

