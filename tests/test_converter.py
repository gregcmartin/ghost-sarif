"""Tests for Ghost to SARIF converter."""

import pytest
import json
from ghost_sarif.converter import GhostToSarifConverter
from ghost_sarif.models import GhostFinding, GhostSeverity, SeverityLevel


class TestGhostToSarifConverter:
    """Test cases for GhostToSarifConverter."""
    
    def setup_method(self):
        """Set up test fixtures."""
        self.converter = GhostToSarifConverter()
        
        # Sample Ghost findings
        self.sample_findings = [
            GhostFinding(
                id="finding-1",
                title="SQL Injection",
                description="SQL injection vulnerability in login form",
                severity=GhostSeverity.HIGH,
                category="injection",
                cwe_id="CWE-89",
                owasp_category="A03:2021 – Injection",
                file_path="/app/login.php",
                line_number=42,
                column_number=15,
                code_snippet="$query = \"SELECT * FROM users WHERE username = '$username'\";",
                remediation="Use parameterized queries to prevent SQL injection",
                references=["https://owasp.org/www-community/attacks/SQL_Injection"]
            ),
            GhostFinding(
                id="finding-2",
                title="Cross-Site Scripting (XSS)",
                description="Reflected XSS vulnerability in search functionality",
                severity=GhostSeverity.MEDIUM,
                category="xss",
                cwe_id="CWE-79",
                file_path="/app/search.php",
                line_number=25,
                remediation="Sanitize user input and encode output"
            ),
            GhostFinding(
                id="finding-3",
                title="Information Disclosure",
                description="Sensitive information exposed in error messages",
                severity=GhostSeverity.LOW,
                category="information_disclosure"
            )
        ]
    
    def test_severity_mapping(self):
        """Test severity level mapping."""
        assert self.converter.severity_mapping[GhostSeverity.CRITICAL] == SeverityLevel.ERROR
        assert self.converter.severity_mapping[GhostSeverity.HIGH] == SeverityLevel.ERROR
        assert self.converter.severity_mapping[GhostSeverity.MEDIUM] == SeverityLevel.WARNING
        assert self.converter.severity_mapping[GhostSeverity.LOW] == SeverityLevel.WARNING
        assert self.converter.severity_mapping[GhostSeverity.INFO] == SeverityLevel.INFO
    
    def test_generate_rule_id_with_cwe(self):
        """Test rule ID generation with CWE ID."""
        finding = self.sample_findings[0]  # Has CWE-89
        rule_id = self.converter._generate_rule_id(finding)
        assert rule_id == "CWE-89"
    
    def test_generate_rule_id_without_cwe(self):
        """Test rule ID generation without CWE ID."""
        finding = self.sample_findings[2]  # No CWE ID
        rule_id = self.converter._generate_rule_id(finding)
        assert rule_id == "GHOST_INFORMATION_DISCLOSURE"
    
    def test_create_rules_from_findings(self):
        """Test SARIF rules creation from findings."""
        rules = self.converter._create_rules_from_findings(self.sample_findings)
        
        assert len(rules) == 3  # Three unique rule types
        
        # Check first rule (SQL Injection)
        sql_rule = next(rule for rule in rules if rule.id == "CWE-89")
        assert sql_rule.name == "injection"
        assert sql_rule.shortDescription.text == "SQL Injection"
        assert "SQL injection vulnerability" in sql_rule.fullDescription.text
        assert sql_rule.helpUri == "https://cwe.mitre.org/data/definitions/89.html"
        assert sql_rule.properties["cwe"] == "CWE-89"
        assert sql_rule.properties["severity"] == "high"
    
    def test_create_location_with_full_info(self):
        """Test location creation with complete information."""
        finding = self.sample_findings[0]  # Has file, line, column, snippet
        location = self.converter._create_location(finding)
        
        assert location is not None
        assert location.physicalLocation["artifactLocation"]["uri"] == "/app/login.php"
        assert location.physicalLocation["region"]["startLine"] == 42
        assert location.physicalLocation["region"]["startColumn"] == 15
        assert "SELECT * FROM users" in location.physicalLocation["region"]["snippet"]["text"]
    
    def test_create_location_minimal_info(self):
        """Test location creation with minimal information."""
        finding = self.sample_findings[1]  # Has file and line only
        location = self.converter._create_location(finding)
        
        assert location is not None
        assert location.physicalLocation["artifactLocation"]["uri"] == "/app/search.php"
        assert location.physicalLocation["region"]["startLine"] == 25
        assert "startColumn" not in location.physicalLocation["region"]
        assert "snippet" not in location.physicalLocation["region"]
    
    def test_create_location_no_file(self):
        """Test location creation without file information."""
        finding = self.sample_findings[2]  # No file path
        location = self.converter._create_location(finding)
        
        assert location is None
    
    def test_convert_finding_to_result(self):
        """Test converting a finding to SARIF result."""
        rules = self.converter._create_rules_from_findings(self.sample_findings)
        finding = self.sample_findings[0]
        
        result = self.converter._convert_finding_to_result(finding, rules)
        
        assert result is not None
        assert result.ruleId == "CWE-89"
        assert result.level == SeverityLevel.ERROR
        assert "SQL Injection" in result.message.text
        assert len(result.locations) == 1
        assert result.properties["ghostId"] == "finding-1"
        assert result.properties["severity"] == "high"
    
    def test_convert_findings_to_sarif(self):
        """Test complete conversion to SARIF format."""
        sarif_report = self.converter.convert_findings_to_sarif(
            self.sample_findings,
            tool_name="Test Tool",
            tool_version="2.0.0"
        )
        
        assert sarif_report.version == "2.1.0"
        assert len(sarif_report.runs) == 1
        
        run = sarif_report.runs[0]
        assert run.tool.driver["name"] == "Test Tool"
        assert run.tool.driver["version"] == "2.0.0"
        assert len(run.tool.driver["rules"]) == 3
        assert len(run.results) == 3
        
        # Check properties
        assert run.properties["totalFindings"] == 3
        assert run.properties["convertedResults"] == 3
        assert "conversionTimestamp" in run.properties
    
    def test_create_help_markdown(self):
        """Test help markdown creation."""
        finding = self.sample_findings[0]
        markdown = self.converter._create_help_markdown(finding)
        
        assert "## SQL Injection" in markdown
        assert "SQL injection vulnerability" in markdown
        assert "### Remediation" in markdown
        assert "Use parameterized queries" in markdown
        assert "**CWE ID:** CWE-89" in markdown
        assert "### References" in markdown
        assert "https://owasp.org" in markdown
    
    def test_get_help_uri_with_cwe(self):
        """Test help URI generation with CWE ID."""
        finding = self.sample_findings[0]
        uri = self.converter._get_help_uri(finding)
        assert uri == "https://cwe.mitre.org/data/definitions/89.html"
    
    def test_get_help_uri_without_cwe(self):
        """Test help URI generation without CWE ID."""
        finding = self.sample_findings[2]
        uri = self.converter._get_help_uri(finding)
        assert uri is None
    
    def test_create_rule_properties(self):
        """Test rule properties creation."""
        finding = self.sample_findings[0]
        properties = self.converter._create_rule_properties(finding)
        
        assert properties["category"] == "injection"
        assert properties["severity"] == "high"
        assert properties["cwe"] == "CWE-89"
        assert properties["owasp"] == "A03:2021 – Injection"
    
    def test_create_result_properties(self):
        """Test result properties creation."""
        finding = self.sample_findings[0]
        properties = self.converter._create_result_properties(finding)
        
        assert properties["ghostId"] == "finding-1"
        assert properties["category"] == "injection"
        assert properties["severity"] == "high"
    
    def test_save_sarif_report(self, tmp_path):
        """Test saving SARIF report to file."""
        sarif_report = self.converter.convert_findings_to_sarif(self.sample_findings)
        output_path = tmp_path / "test_output.sarif"
        
        self.converter.save_sarif_report(sarif_report, str(output_path))
        
        assert output_path.exists()
        
        # Verify file content
        with open(output_path, 'r') as f:
            saved_data = json.load(f)
        
        assert saved_data["version"] == "2.1.0"
        assert "$schema" in saved_data
        assert len(saved_data["runs"]) == 1
        assert len(saved_data["runs"][0]["results"]) == 3
    
    def test_convert_and_save(self, tmp_path):
        """Test complete convert and save workflow."""
        output_path = tmp_path / "complete_test.sarif"
        
        sarif_report = self.converter.convert_and_save(
            self.sample_findings,
            str(output_path),
            tool_name="Integration Test",
            tool_version="3.0.0"
        )
        
        assert output_path.exists()
        assert sarif_report.version == "2.1.0"
        
        # Verify saved content matches returned object
        with open(output_path, 'r') as f:
            saved_data = json.load(f)
        
        assert saved_data["runs"][0]["tool"]["driver"]["name"] == "Integration Test"
        assert saved_data["runs"][0]["tool"]["driver"]["version"] == "3.0.0"
    
    def test_empty_findings_list(self):
        """Test conversion with empty findings list."""
        sarif_report = self.converter.convert_findings_to_sarif([])
        
        assert len(sarif_report.runs) == 1
        assert len(sarif_report.runs[0].results) == 0
        assert len(sarif_report.runs[0].tool.driver["rules"]) == 0
        assert sarif_report.runs[0].properties["totalFindings"] == 0
        assert sarif_report.runs[0].properties["convertedResults"] == 0
    
    def test_duplicate_rule_handling(self):
        """Test that duplicate rules are handled correctly."""
        # Create two findings with the same CWE
        duplicate_findings = [
            GhostFinding(
                id="finding-1",
                title="SQL Injection 1",
                description="First SQL injection",
                severity=GhostSeverity.HIGH,
                category="injection",
                cwe_id="CWE-89"
            ),
            GhostFinding(
                id="finding-2", 
                title="SQL Injection 2",
                description="Second SQL injection",
                severity=GhostSeverity.MEDIUM,
                category="injection",
                cwe_id="CWE-89"
            )
        ]
        
        rules = self.converter._create_rules_from_findings(duplicate_findings)
        
        # Should only create one rule for the duplicate CWE
        assert len(rules) == 1
        assert rules[0].id == "CWE-89"


if __name__ == "__main__":
    pytest.main([__file__])
