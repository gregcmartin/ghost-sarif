"""Ghost API client for fetching security findings."""

import requests
import logging
from typing import List, Optional, Dict, Any
from .models import GhostFinding, GhostScan, GhostApiResponse


class GhostClientError(Exception):
    """Custom exception for Ghost API client errors."""
    pass


class GhostClient:
    """Client for interacting with Ghost Security API."""
    
    def __init__(self, api_key: str, base_url: str = "https://api.ghostsecurity.ai"):
        """
        Initialize Ghost API client.
        
        Args:
            api_key: Ghost API key
            base_url: Base URL for Ghost API
        """
        self.api_key = api_key
        self.base_url = base_url.rstrip('/')
        self.session = requests.Session()
        self.session.headers.update({
            'Authorization': f'Bearer {api_key}',
            'Content-Type': 'application/json',
            'Accept': 'application/json'
        })
        
        # Set up logging
        self.logger = logging.getLogger(__name__)
    
    def _make_request(self, method: str, endpoint: str, **kwargs) -> Dict[str, Any]:
        """
        Make HTTP request to Ghost API.
        
        Args:
            method: HTTP method
            endpoint: API endpoint
            **kwargs: Additional request parameters
            
        Returns:
            Response data as dictionary
            
        Raises:
            GhostClientError: If request fails
        """
        url = f"{self.base_url}/{endpoint.lstrip('/')}"
        
        try:
            self.logger.debug(f"Making {method} request to {url}")
            response = self.session.request(method, url, **kwargs)
            response.raise_for_status()
            
            return response.json()
            
        except requests.exceptions.HTTPError as e:
            error_msg = f"HTTP error {response.status_code}: {response.text}"
            self.logger.error(error_msg)
            raise GhostClientError(error_msg) from e
            
        except requests.exceptions.RequestException as e:
            error_msg = f"Request failed: {str(e)}"
            self.logger.error(error_msg)
            raise GhostClientError(error_msg) from e
            
        except ValueError as e:
            error_msg = f"Invalid JSON response: {str(e)}"
            self.logger.error(error_msg)
            raise GhostClientError(error_msg) from e
    
    def get_scans(self, limit: int = 100, offset: int = 0) -> List[GhostScan]:
        """
        Get list of scans.
        
        Args:
            limit: Maximum number of scans to return
            offset: Number of scans to skip
            
        Returns:
            List of GhostScan objects
        """
        params = {'limit': limit, 'offset': offset}
        data = self._make_request('GET', '/v1/scans', params=params)
        
        scans = []
        if 'data' in data and isinstance(data['data'], list):
            for scan_data in data['data']:
                try:
                    scan = GhostScan(**scan_data)
                    scans.append(scan)
                except Exception as e:
                    self.logger.warning(f"Failed to parse scan data: {e}")
                    continue
        
        return scans
    
    def get_scan(self, scan_id: str) -> Optional[GhostScan]:
        """
        Get specific scan by ID.
        
        Args:
            scan_id: Scan identifier
            
        Returns:
            GhostScan object or None if not found
        """
        try:
            data = self._make_request('GET', f'/v1/scans/{scan_id}')
            
            if 'data' in data:
                return GhostScan(**data['data'])
                
        except GhostClientError as e:
            self.logger.error(f"Failed to get scan {scan_id}: {e}")
            
        return None
    
    def get_findings(self, scan_id: Optional[str] = None, limit: int = 1000, cursor: Optional[str] = None) -> tuple[List[GhostFinding], Optional[str], bool]:
        """
        Get security findings with cursor-based pagination.
        
        Args:
            scan_id: Optional scan ID to filter findings
            limit: Maximum number of findings to return
            cursor: Pagination cursor for next page
            
        Returns:
            Tuple of (findings_list, next_cursor, has_more)
        """
        params = {'limit': limit}
        if scan_id:
            params['scan_id'] = scan_id
        if cursor:
            params['cursor'] = cursor
            
        endpoint = '/v1/findings'
        data = self._make_request('GET', endpoint, params=params)
        
        findings = []
        # Handle both 'items' (actual API) and 'data' (for backward compatibility)
        items_key = 'items' if 'items' in data else 'data'
        if items_key in data and isinstance(data[items_key], list):
            for finding_data in data[items_key]:
                try:
                    # Handle different possible field names from API
                    normalized_data = self._normalize_finding_data(finding_data)
                    finding = GhostFinding(**normalized_data)
                    findings.append(finding)
                except Exception as e:
                    self.logger.warning(f"Failed to parse finding data: {e}")
                    continue
        
        # Return pagination info
        next_cursor = data.get('next_cursor')
        has_more = data.get('has_more', False)
        
        return findings, next_cursor, has_more
    
    def _normalize_finding_data(self, data: Dict[str, Any]) -> Dict[str, Any]:
        """
        Normalize finding data to match our model.
        
        Args:
            data: Raw finding data from API
            
        Returns:
            Normalized finding data
        """
        # Map Ghost API field names to our model
        field_mappings = {
            'name': 'title',  # Ghost uses 'name' for vulnerability title
            'class': 'category',  # Ghost uses 'class' for vulnerability category
            # Keep other mappings for flexibility
            'vulnerability_id': 'id',
            'vuln_id': 'id',
            'summary': 'description',
            'details': 'description',
            'risk_level': 'severity',
            'severity_level': 'severity',
            'vulnerability_type': 'category',
            'vuln_type': 'category',
            'cwe': 'cwe_id',
            'file': 'file_path',
            'filename': 'file_path',
            'line': 'line_number',
            'column': 'column_number',
            'snippet': 'code_snippet',
            'fix': 'remediation',
            'solution': 'remediation',
            'urls': 'references',
            'links': 'references'
        }
        
        normalized = {}
        for key, value in data.items():
            # Use mapped field name if available, otherwise use original
            normalized_key = field_mappings.get(key, key)
            normalized[normalized_key] = value
        
        # Ensure required fields have default values
        if 'id' not in normalized:
            normalized['id'] = str(data.get('_id', 'unknown'))
        if 'title' not in normalized:
            normalized['title'] = 'Unknown Vulnerability'
        if 'description' not in normalized:
            normalized['description'] = 'No description available'
        if 'severity' not in normalized:
            normalized['severity'] = 'medium'
        if 'category' not in normalized:
            normalized['category'] = 'security'
            
        return normalized
    
    def get_all_findings(self, scan_id: Optional[str] = None) -> List[GhostFinding]:
        """
        Get all findings with cursor-based pagination.
        
        Args:
            scan_id: Optional scan ID to filter findings
            
        Returns:
            List of all GhostFinding objects
        """
        all_findings = []
        cursor = None
        limit = 1000
        
        while True:
            findings, next_cursor, has_more = self.get_findings(
                scan_id=scan_id, 
                limit=limit, 
                cursor=cursor
            )
            
            if not findings:
                break
                
            all_findings.extend(findings)
            self.logger.debug(f"Retrieved {len(findings)} findings, total so far: {len(all_findings)}")
            
            # Check if there are more pages
            if not has_more or not next_cursor:
                break
                
            cursor = next_cursor
        
        self.logger.info(f"Retrieved {len(all_findings)} total findings")
        return all_findings
