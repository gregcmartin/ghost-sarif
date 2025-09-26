"""Command-line interface for Ghost SARIF converter."""

import click
import logging
import sys
import os
from pathlib import Path
from typing import Optional

try:
    from dotenv import load_dotenv
    load_dotenv()
except ImportError:
    # python-dotenv not installed, skip loading .env file
    pass

from .client import GhostClient, GhostClientError
from .converter import GhostToSarifConverter


def setup_logging(verbose: bool = False) -> None:
    """Set up logging configuration."""
    level = logging.DEBUG if verbose else logging.INFO
    logging.basicConfig(
        level=level,
        format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
        handlers=[
            logging.StreamHandler(sys.stdout)
        ]
    )


@click.group()
@click.option('--verbose', '-v', is_flag=True, help='Enable verbose logging')
@click.pass_context
def cli(ctx, verbose):
    """Ghost SARIF converter - Convert Ghost security findings to SARIF format."""
    ctx.ensure_object(dict)
    ctx.obj['verbose'] = verbose
    setup_logging(verbose)


@cli.command()
@click.option('--api-key', '-k', 
              default=lambda: os.getenv('GHOST_API_KEY'), 
              help='Ghost API key (or set GHOST_API_KEY env var)')
@click.option('--base-url', '-u', 
              default=lambda: os.getenv('GHOST_BASE_URL', 'https://api.ghostsecurity.ai'), 
              help='Ghost API base URL (or set GHOST_BASE_URL env var)')
@click.option('--scan-id', '-s', help='Specific scan ID to fetch findings from')
@click.option('--output', '-o', 
              default=lambda: os.getenv('DEFAULT_OUTPUT_PATH', 'ghost-findings.sarif'), 
              help='Output SARIF file path (or set DEFAULT_OUTPUT_PATH env var)')
@click.option('--tool-name', 
              default=lambda: os.getenv('DEFAULT_TOOL_NAME', 'Ghost Security'), 
              help='Tool name in SARIF report (or set DEFAULT_TOOL_NAME env var)')
@click.option('--tool-version', 
              default=lambda: os.getenv('DEFAULT_TOOL_VERSION', '1.0.0'), 
              help='Tool version in SARIF report (or set DEFAULT_TOOL_VERSION env var)')
@click.pass_context
def convert(ctx, api_key, base_url, scan_id, output, tool_name, tool_version):
    """Convert Ghost findings to SARIF format."""
    verbose = ctx.obj.get('verbose', False)
    logger = logging.getLogger(__name__)
    
    # Validate API key
    if not api_key:
        click.echo("Error: Ghost API key is required. Set GHOST_API_KEY environment variable or use --api-key option.", err=True)
        sys.exit(1)
    
    try:
        # Initialize Ghost client
        logger.info("Initializing Ghost API client...")
        client = GhostClient(api_key=api_key, base_url=base_url)
        
        # Fetch findings
        logger.info("Fetching findings from Ghost API...")
        if scan_id:
            logger.info(f"Fetching findings for scan ID: {scan_id}")
            findings = client.get_all_findings(scan_id=scan_id)
        else:
            logger.info("Fetching all findings")
            findings = client.get_all_findings()
        
        if not findings:
            logger.warning("No findings retrieved from Ghost API")
            click.echo("No findings found to convert.")
            return
        
        logger.info(f"Retrieved {len(findings)} findings")
        
        # Convert to SARIF
        logger.info("Converting findings to SARIF format...")
        converter = GhostToSarifConverter()
        sarif_report = converter.convert_and_save(
            findings=findings,
            output_path=output,
            tool_name=tool_name,
            tool_version=tool_version
        )
        
        # Display summary
        total_results = len(sarif_report.runs[0].results) if sarif_report.runs else 0
        click.echo(f"Successfully converted {len(findings)} findings to SARIF format")
        click.echo(f"SARIF report saved to: {output}")
        click.echo(f"Total results in SARIF: {total_results}")
        
        if verbose:
            # Show severity breakdown
            severity_counts = {}
            for finding in findings:
                severity = finding.severity.value
                severity_counts[severity] = severity_counts.get(severity, 0) + 1
            
            click.echo("\nSeverity breakdown:")
            for severity, count in sorted(severity_counts.items()):
                click.echo(f"  {severity.upper()}: {count}")
        
    except GhostClientError as e:
        logger.error(f"Ghost API error: {e}")
        click.echo(f"Error connecting to Ghost API: {e}", err=True)
        sys.exit(1)
        
    except Exception as e:
        logger.error(f"Unexpected error: {e}")
        click.echo(f"Unexpected error: {e}", err=True)
        sys.exit(1)


@cli.command()
@click.option('--api-key', '-k', 
              default=lambda: os.getenv('GHOST_API_KEY'), 
              help='Ghost API key (or set GHOST_API_KEY env var)')
@click.option('--base-url', '-u', 
              default=lambda: os.getenv('GHOST_BASE_URL', 'https://api.ghostsecurity.ai'), 
              help='Ghost API base URL (or set GHOST_BASE_URL env var)')
@click.pass_context
def list_scans(ctx, api_key, base_url):
    """List available scans from Ghost API."""
    verbose = ctx.obj.get('verbose', False)
    logger = logging.getLogger(__name__)
    
    try:
        # Initialize Ghost client
        logger.info("Initializing Ghost API client...")
        client = GhostClient(api_key=api_key, base_url=base_url)
        
        # Fetch scans
        logger.info("Fetching scans from Ghost API...")
        scans = client.get_scans(limit=50)
        
        if not scans:
            click.echo("No scans found.")
            return
        
        click.echo(f"Found {len(scans)} scans:\n")
        
        for scan in scans:
            status_indicator = "[COMPLETED]" if scan.status == "completed" else "[RUNNING]" if scan.status == "running" else "[FAILED]"
            click.echo(f"{status_indicator} {scan.name}")
            click.echo(f"   ID: {scan.id}")
            click.echo(f"   Status: {scan.status}")
            click.echo(f"   Created: {scan.created_at}")
            if hasattr(scan, 'findings') and scan.findings:
                click.echo(f"   Findings: {len(scan.findings)}")
            click.echo()
        
    except GhostClientError as e:
        logger.error(f"Ghost API error: {e}")
        click.echo(f"Error connecting to Ghost API: {e}", err=True)
        sys.exit(1)
        
    except Exception as e:
        logger.error(f"Unexpected error: {e}")
        click.echo(f"Unexpected error: {e}", err=True)
        sys.exit(1)


@cli.command()
@click.option('--api-key', '-k', 
              default=lambda: os.getenv('GHOST_API_KEY'), 
              help='Ghost API key (or set GHOST_API_KEY env var)')
@click.option('--base-url', '-u', 
              default=lambda: os.getenv('GHOST_BASE_URL', 'https://api.ghostsecurity.ai'), 
              help='Ghost API base URL (or set GHOST_BASE_URL env var)')
@click.option('--scan-id', '-s', help='Specific scan ID to get findings from')
@click.option('--limit', '-l', default=10, help='Maximum number of findings to display')
@click.pass_context
def list_findings(ctx, api_key, base_url, scan_id, limit):
    """List findings from Ghost API."""
    verbose = ctx.obj.get('verbose', False)
    logger = logging.getLogger(__name__)
    
    try:
        # Initialize Ghost client
        logger.info("Initializing Ghost API client...")
        client = GhostClient(api_key=api_key, base_url=base_url)
        
        # Fetch findings
        logger.info("Fetching findings from Ghost API...")
        findings, _, _ = client.get_findings(scan_id=scan_id, limit=limit)
        
        if not findings:
            click.echo("No findings found.")
            return
        
        click.echo(f"Found {len(findings)} findings:\n")
        
        for i, finding in enumerate(findings, 1):
            severity_indicator = f"[{finding.severity.value.upper()}]"
            
            click.echo(f"{i}. {severity_indicator} {finding.title}")
            click.echo(f"   ID: {finding.id}")
            click.echo(f"   Severity: {finding.severity.value.upper()}")
            click.echo(f"   Category: {finding.category}")
            
            if finding.file_path:
                location = finding.file_path
                if finding.line_number:
                    location += f":{finding.line_number}"
                click.echo(f"   Location: {location}")
            
            if verbose:
                click.echo(f"   Description: {finding.description[:100]}...")
                if finding.cwe_id:
                    click.echo(f"   CWE: {finding.cwe_id}")
            
            click.echo()
        
        if len(findings) == limit:
            click.echo(f"Showing first {limit} findings. Use --limit to see more.")
        
    except GhostClientError as e:
        logger.error(f"Ghost API error: {e}")
        click.echo(f"Error connecting to Ghost API: {e}", err=True)
        sys.exit(1)
        
    except Exception as e:
        logger.error(f"Unexpected error: {e}")
        click.echo(f"Unexpected error: {e}", err=True)
        sys.exit(1)


@cli.command()
@click.argument('sarif_file', type=click.Path(exists=True))
def validate(sarif_file):
    """Validate a SARIF file."""
    import json
    
    try:
        with open(sarif_file, 'r') as f:
            sarif_data = json.load(f)
        
        # Basic validation
        required_fields = ['version', '$schema', 'runs']
        missing_fields = [field for field in required_fields if field not in sarif_data]
        
        if missing_fields:
            click.echo(f"Invalid SARIF file. Missing required fields: {', '.join(missing_fields)}")
            sys.exit(1)
        
        if sarif_data.get('version') != '2.1.0':
            click.echo(f"Warning: SARIF version is {sarif_data.get('version')}, expected 2.1.0")
        
        runs = sarif_data.get('runs', [])
        total_results = sum(len(run.get('results', [])) for run in runs)
        
        click.echo(f"Valid SARIF file: {sarif_file}")
        click.echo(f"Runs: {len(runs)}")
        click.echo(f"Total results: {total_results}")
        
        if runs:
            for i, run in enumerate(runs):
                tool_name = run.get('tool', {}).get('driver', {}).get('name', 'Unknown')
                results_count = len(run.get('results', []))
                click.echo(f"   Run {i+1}: {tool_name} ({results_count} results)")
        
    except json.JSONDecodeError as e:
        click.echo(f"Invalid JSON in SARIF file: {e}")
        sys.exit(1)
        
    except Exception as e:
        click.echo(f"Error validating SARIF file: {e}")
        sys.exit(1)


if __name__ == '__main__':
    cli()
