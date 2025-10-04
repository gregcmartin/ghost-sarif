"""Tests for Ghost API client."""

import pytest
import responses
from unittest.mock import Mock, patch
from ghost_sarif.client import GhostClient, GhostClientError
from ghost_sarif.models import GhostFinding, GhostScan, GhostSeverity


class TestGhostClient:
    """Test cases for GhostClient."""
    
    def setup_method(self):
        """Set up test fixtures."""
        self.api_key = "test-api-key"
        self.base_url = "https://api.test.com"
        self.client = GhostClient(api_key=self.api_key, base_url=self.base_url)
    
    def test_init(self):
        """Test client initialization."""
        assert self.client.api_key == self.api_key
        assert self.client.base_url == self.base_url
        assert "Bearer test-api-key" in self.client.session.headers["Authorization"]
    
    @responses.activate
    def test_get_scans_success(self):
        """Test successful scans retrieval."""
        mock_response = {
            "data": [
                {
                    "id": "scan-1",
                    "name": "Test Scan 1",
                    "status": "completed",
                    "created_at": "2023-01-01T00:00:00Z",
                    "updated_at": "2023-01-01T01:00:00Z"
                },
                {
                    "id": "scan-2", 
                    "name": "Test Scan 2",
                    "status": "running",
                    "created_at": "2023-01-02T00:00:00Z",
                    "updated_at": "2023-01-02T01:00:00Z"
                }
            ]
        }
        
        responses.add(
            responses.GET,
            f"{self.base_url}/v1/scans",
            json=mock_response,
            status=200
        )
        
        scans = self.client.get_scans()
        
        assert len(scans) == 2
        assert scans[0].id == "scan-1"
        assert scans[0].name == "Test Scan 1"
        assert scans[1].id == "scan-2"
        assert scans[1].status == "running"
    
    @responses.activate
    def test_get_findings_success(self):
        """Test successful findings retrieval."""
        mock_response = {
            "data": [
                {
                    "id": "finding-1",
                    "title": "SQL Injection",
                    "description": "SQL injection vulnerability found",
                    "severity": "high",
                    "category": "injection",
                    "file_path": "/app/login.php",
                    "line_number": 42,
                    "cwe_id": "CWE-89"
                },
                {
                    "id": "finding-2",
                    "title": "XSS Vulnerability", 
                    "description": "Cross-site scripting vulnerability",
                    "severity": "medium",
                    "category": "xss",
                    "file_path": "/app/search.php",
                    "line_number": 15
                }
            ]
        }
        
        responses.add(
            responses.GET,
            f"{self.base_url}/v1/findings",
            json=mock_response,
            status=200
        )
        
        findings, next_cursor, has_more = self.client.get_findings()
        
        assert len(findings) == 2
        assert next_cursor is None
        assert has_more is False
        assert findings[0].id == "finding-1"
        assert findings[0].title == "SQL Injection"
        assert findings[0].severity == GhostSeverity.HIGH
        assert findings[0].file_path == "/app/login.php"
        assert findings[0].line_number == 42
        assert findings[1].id == "finding-2"
        assert findings[1].severity == GhostSeverity.MEDIUM
    
    @responses.activate
    def test_get_findings_with_project_id(self):
        """Test findings retrieval with project ID filter (client-side)."""
        mock_response = {
            "items": [
                {
                    "id": "finding-1",
                    "project_id": "test-project-id",
                    "name": "Test Finding 1",
                    "description": "Test description 1",
                    "severity": "high",
                    "class": "security"
                },
                {
                    "id": "finding-2",
                    "project_id": "other-project-id",
                    "name": "Test Finding 2",
                    "description": "Test description 2",
                    "severity": "medium",
                    "class": "security"
                }
            ],
            "has_more": False,
            "next_cursor": None
        }

        responses.add(
            responses.GET,
            f"{self.base_url}/v1/findings",
            json=mock_response,
            status=200
        )

        findings, _, _ = self.client.get_findings(project_id="test-project-id")

        # Check that only matching findings were returned (client-side filtering)
        assert len(findings) == 1
        assert findings[0].id == "finding-1"
        # Verify size parameter was used instead of scan_id
        assert len(responses.calls) == 1
        request = responses.calls[0].request
        assert "size=" in request.url
        assert "scan_id" not in request.url
    
    @responses.activate
    def test_api_error_handling(self):
        """Test API error handling."""
        responses.add(
            responses.GET,
            f"{self.base_url}/v1/scans",
            json={"error": "Unauthorized"},
            status=401
        )
        
        with pytest.raises(GhostClientError) as exc_info:
            self.client.get_scans()
        
        assert "HTTP error 401" in str(exc_info.value)
    
    def test_normalize_finding_data(self):
        """Test finding data normalization."""
        raw_data = {
            "vulnerability_id": "vuln-123",
            "name": "Test Vulnerability",
            "summary": "Test description",
            "risk_level": "high",
            "vulnerability_type": "injection",
            "file": "/test/file.php",
            "line": 10,
            "cwe": "CWE-89"
        }

        normalized = self.client._normalize_finding_data(raw_data)

        assert normalized["id"] == "vuln-123"
        assert normalized["title"] == "Test Vulnerability"
        assert normalized["description"] == "Test description"
        assert normalized["severity"] == "high"
        assert normalized["category"] == "injection"
        assert normalized["file_path"] == "/test/file.php"
        assert normalized["line_number"] == 10
        assert normalized["cwe_id"] == "CWE-89"

    def test_normalize_finding_data_with_location_object(self):
        """Test finding data normalization with nested location object."""
        raw_data = {
            "id": "vuln-456",
            "name": "SQL Injection",
            "description": "SQL injection vulnerability",
            "severity": "critical",
            "class": "injection",
            "location": {
                "file_path": "/app/login.php",
                "line_number": 42,
                "column_number": 10
            },
            "vulnerable_code_block": "$query = \"SELECT * FROM users WHERE id = \" . $_GET['id'];"
        }

        normalized = self.client._normalize_finding_data(raw_data)

        assert normalized["file_path"] == "/app/login.php"
        assert normalized["line_number"] == 42
        assert normalized["column_number"] == 10
        assert normalized["code_snippet"] == "$query = \"SELECT * FROM users WHERE id = \" . $_GET['id'];"
    
    def test_normalize_finding_data_with_defaults(self):
        """Test finding data normalization with missing required fields."""
        raw_data = {
            "some_field": "some_value"
        }
        
        normalized = self.client._normalize_finding_data(raw_data)
        
        assert "id" in normalized
        assert normalized["title"] == "Unknown Vulnerability"
        assert normalized["description"] == "No description available"
        assert normalized["severity"] == "medium"
        assert normalized["category"] == "security"
    
    @responses.activate
    def test_get_all_findings_pagination(self):
        """Test cursor-based pagination in get_all_findings."""
        # First page with cursor
        responses.add(
            responses.GET,
            f"{self.base_url}/v1/findings",
            json={
                "items": [
                    {
                        "id": f"finding-{i}",
                        "title": f"Finding {i}",
                        "description": f"Description {i}",
                        "severity": "medium",
                        "category": "test"
                    }
                    for i in range(100)  # Full page
                ],
                "next_cursor": "test-cursor-123",
                "has_more": True
            },
            status=200
        )
        
        # Second page (final)
        responses.add(
            responses.GET,
            f"{self.base_url}/v1/findings",
            json={
                "items": [
                    {
                        "id": f"finding-{i}",
                        "title": f"Finding {i}",
                        "description": f"Description {i}",
                        "severity": "medium",
                        "category": "test"
                    }
                    for i in range(100, 124)  # Partial page
                ],
                "next_cursor": None,
                "has_more": False
            },
            status=200
        )
        
        findings = self.client.get_all_findings()
        
        assert len(findings) == 124
        assert len(responses.calls) == 2

        # Check pagination parameters (using 'size' not 'limit')
        first_call = responses.calls[0].request
        assert "size=1000" in first_call.url
        assert "cursor=" not in first_call.url  # No cursor on first call

        second_call = responses.calls[1].request
        assert "size=1000" in second_call.url
        assert "cursor=test-cursor-123" in second_call.url


if __name__ == "__main__":
    pytest.main([__file__])
