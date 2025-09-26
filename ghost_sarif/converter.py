"""Converter to transform Ghost security findings to SARIF format."""

import json
import logging
from typing import List, Dict, Any, Optional
from datetime import datetime
from .models import (
    GhostFinding, GhostSeverity, SeverityLevel,
    SarifReport, SarifRun, SarifTool, SarifResult, 
    SarifMessage, SarifLocation, SarifRule
)


class GhostToSarifConverter:
    """Converts Ghost security findings to SARIF format."""
    
    def __init__(self):
        """Initialize the converter."""
        self.logger = logging.getLogger(__name__)
        
        # Mapping from Ghost severity to SARIF level
        self.severity_mapping = {
            GhostSeverity.CRITICAL: SeverityLevel.ERROR,
            GhostSeverity.HIGH: SeverityLevel.ERROR,
            GhostSeverity.MEDIUM: SeverityLevel.WARNING,
            GhostSeverity.LOW: SeverityLevel.WARNING,
            GhostSeverity.INFO: SeverityLevel.INFO
        }
    
    def convert_findings_to_sarif(
        self, 
        findings: List[GhostFinding], 
        tool_name: str = "Ghost Security",
        tool_version: str = "1.0.0"
    ) -> SarifReport:
        """
        Convert Ghost findings to SARIF format.
        
        Args:
            findings: List of Ghost findings
            tool_name: Name of the scanning tool
            tool_version: Version of the scanning tool
            
        Returns:
            SARIF report object
        """
        self.logger.info(f"Converting {len(findings)} findings to SARIF format")
        
        # Create rules from unique finding types
        rules = self._create_rules_from_findings(findings)
        
        # Create results from findings
        results = []
        for finding in findings:
            try:
                result = self._convert_finding_to_result(finding, rules)
                if result:
                    results.append(result)
            except Exception as e:
                self.logger.warning(f"Failed to convert finding {finding.id}: {e}")
                continue
        
        # Create SARIF tool definition
        tool = SarifTool(
            driver={
                "name": tool_name,
                "version": tool_version,
                "informationUri": "https://ghostsecurity.ai",
                "rules": [rule.dict(exclude_none=True) for rule in rules]
            }
        )
        
        # Create SARIF run
        run = SarifRun(
            tool=tool,
            results=results,
            properties={
                "conversionTimestamp": datetime.utcnow().isoformat() + "Z",
                "totalFindings": len(findings),
                "convertedResults": len(results)
            }
        )
        
        # Create SARIF report
        sarif_report = SarifReport(runs=[run])
        
        self.logger.info(f"Successfully converted {len(results)} findings to SARIF")
        return sarif_report
    
    def _create_rules_from_findings(self, findings: List[GhostFinding]) -> List[SarifRule]:
        """
        Create SARIF rules from unique finding types.
        
        Args:
            findings: List of Ghost findings
            
        Returns:
            List of SARIF rules
        """
        rules_dict = {}
        
        for finding in findings:
            rule_id = self._generate_rule_id(finding)
            
            if rule_id not in rules_dict:
                rule = SarifRule(
                    id=rule_id,
                    name=finding.category,
                    shortDescription=SarifMessage(text=finding.title),
                    fullDescription=SarifMessage(text=finding.description),
                    help=SarifMessage(
                        text=finding.remediation or "No remediation guidance available",
                        markdown=self._create_help_markdown(finding)
                    ),
                    helpUri=self._get_help_uri(finding),
                    properties=self._create_rule_properties(finding)
                )
                rules_dict[rule_id] = rule
        
        return list(rules_dict.values())
    
    def _convert_finding_to_result(
        self, 
        finding: GhostFinding, 
        rules: List[SarifRule]
    ) -> Optional[SarifResult]:
        """
        Convert a Ghost finding to a SARIF result.
        
        Args:
            finding: Ghost finding
            rules: List of available rules
            
        Returns:
            SARIF result or None if conversion fails
        """
        rule_id = self._generate_rule_id(finding)
        
        # Find rule index
        rule_index = None
        for i, rule in enumerate(rules):
            if rule.id == rule_id:
                rule_index = i
                break
        
        # Convert severity
        level = self.severity_mapping.get(finding.severity, SeverityLevel.WARNING)
        
        # Create message
        message = SarifMessage(
            text=f"{finding.title}: {finding.description}"
        )
        
        # Create locations if file information is available
        locations = []
        if finding.file_path:
            location = self._create_location(finding)
            if location:
                locations.append(location)
        
        # Create result
        result = SarifResult(
            ruleId=rule_id,
            ruleIndex=rule_index,
            level=level,
            message=message,
            locations=locations if locations else None,
            properties=self._create_result_properties(finding)
        )
        
        return result
    
    def _create_location(self, finding: GhostFinding) -> Optional[SarifLocation]:
        """
        Create SARIF location from Ghost finding.
        
        Args:
            finding: Ghost finding
            
        Returns:
            SARIF location or None
        """
        if not finding.file_path:
            return None
        
        physical_location = {
            "artifactLocation": {
                "uri": finding.file_path
            }
        }
        
        # Add region information if available
        if finding.line_number:
            region = {
                "startLine": finding.line_number
            }
            
            if finding.column_number:
                region["startColumn"] = finding.column_number
            
            if finding.code_snippet:
                region["snippet"] = {
                    "text": finding.code_snippet
                }
            
            physical_location["region"] = region
        
        return SarifLocation(physicalLocation=physical_location)
    
    def _generate_rule_id(self, finding: GhostFinding) -> str:
        """
        Generate a rule ID from a finding.
        
        Args:
            finding: Ghost finding
            
        Returns:
            Rule ID string
        """
        # Use CWE ID if available, otherwise use category
        if finding.cwe_id:
            return f"CWE-{finding.cwe_id.replace('CWE-', '')}"
        
        # Create ID from category
        category = finding.category.replace(' ', '_').replace('-', '_').upper()
        return f"GHOST_{category}"
    
    def _create_help_markdown(self, finding: GhostFinding) -> str:
        """
        Create help markdown for a finding.
        
        Args:
            finding: Ghost finding
            
        Returns:
            Markdown help text
        """
        markdown_parts = [f"## {finding.title}", "", finding.description]
        
        if finding.remediation:
            markdown_parts.extend(["", "### Remediation", finding.remediation])
        
        if finding.cwe_id:
            markdown_parts.extend(["", f"**CWE ID:** {finding.cwe_id}"])
        
        if finding.owasp_category:
            markdown_parts.extend(["", f"**OWASP Category:** {finding.owasp_category}"])
        
        if finding.references:
            markdown_parts.extend(["", "### References"])
            for ref in finding.references:
                markdown_parts.append(f"- {ref}")
        
        return "\n".join(markdown_parts)
    
    def _get_help_uri(self, finding: GhostFinding) -> Optional[str]:
        """
        Get help URI for a finding.
        
        Args:
            finding: Ghost finding
            
        Returns:
            Help URI or None
        """
        if finding.cwe_id:
            cwe_num = finding.cwe_id.replace('CWE-', '')
            return f"https://cwe.mitre.org/data/definitions/{cwe_num}.html"
        
        return None
    
    def _create_rule_properties(self, finding: GhostFinding) -> Dict[str, Any]:
        """
        Create rule properties from finding.
        
        Args:
            finding: Ghost finding
            
        Returns:
            Properties dictionary
        """
        properties = {
            "category": finding.category,
            "severity": finding.severity.value
        }
        
        if finding.cwe_id:
            properties["cwe"] = finding.cwe_id
        
        if finding.owasp_category:
            properties["owasp"] = finding.owasp_category
        
        return properties
    
    def _create_result_properties(self, finding: GhostFinding) -> Dict[str, Any]:
        """
        Create result properties from finding.
        
        Args:
            finding: Ghost finding
            
        Returns:
            Properties dictionary
        """
        properties = {
            "ghostId": finding.id,
            "category": finding.category,
            "severity": finding.severity.value
        }
        
        if finding.status:
            properties["status"] = finding.status
        
        if finding.confidence:
            properties["confidence"] = finding.confidence
        
        if finding.created_at:
            properties["createdAt"] = finding.created_at
        
        if finding.updated_at:
            properties["updatedAt"] = finding.updated_at
        
        return properties
    
    def save_sarif_report(self, sarif_report: SarifReport, output_path: str) -> None:
        """
        Save SARIF report to file.
        
        Args:
            sarif_report: SARIF report object
            output_path: Output file path
        """
        try:
            with open(output_path, 'w', encoding='utf-8') as f:
                # Convert to dict and handle the schema field alias
                report_dict = sarif_report.dict(by_alias=True, exclude_none=True)
                json.dump(report_dict, f, indent=2, ensure_ascii=False)
            
            self.logger.info(f"SARIF report saved to {output_path}")
            
        except Exception as e:
            self.logger.error(f"Failed to save SARIF report: {e}")
            raise
    
    def convert_and_save(
        self, 
        findings: List[GhostFinding], 
        output_path: str,
        tool_name: str = "Ghost Security",
        tool_version: str = "1.0.0"
    ) -> SarifReport:
        """
        Convert findings to SARIF and save to file.
        
        Args:
            findings: List of Ghost findings
            output_path: Output file path
            tool_name: Name of the scanning tool
            tool_version: Version of the scanning tool
            
        Returns:
            SARIF report object
        """
        sarif_report = self.convert_findings_to_sarif(
            findings, tool_name, tool_version
        )
        self.save_sarif_report(sarif_report, output_path)
        return sarif_report
