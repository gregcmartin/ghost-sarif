# Ghost SARIF Converter

An API client for the Ghost Application Security platform that fetches vulnerability findings and converts them to SARIF (Static Analysis Results Interchange Format) output files.

## Features

- **Ghost API Integration**: Connect to Ghost Security platform using API keys
- **SARIF Conversion**: Convert Ghost findings to industry-standard SARIF 2.1.0 format
- **Comprehensive Mapping**: Maps Ghost severity levels, CWE IDs, and OWASP categories to SARIF
- **Location Tracking**: Preserves file paths, line numbers, and code snippets
- **CLI Interface**: Easy-to-use command-line tools
- **Flexible Filtering**: Filter by scan ID or retrieve all findings
- **Validation**: Built-in SARIF validation capabilities
- **Well Tested**: Comprehensive test suite for production reliability

## Installation

### From Source

```bash
git clone <repository-url>
cd Ghost-SARIF
pip install -r requirements.txt
pip install -e .
```

### Using pip (when published)

```bash
pip install ghost-sarif
```

## Quick Start

### Environment Setup

1. **Copy the environment template:**
   ```bash
   cp .env.example .env
   ```

2. **Edit `.env` file with your Ghost API credentials:**
   ```bash
   GHOST_API_KEY=your-ghost-api-key-here
   GHOST_BASE_URL=https://api.ghostsecurity.ai
   ```

### Command Line Usage

```bash
# Convert all findings to SARIF (using environment variables)
ghost-sarif convert --output findings.sarif

# Or specify API key directly
ghost-sarif convert --api-key YOUR_API_KEY --output findings.sarif

# Convert findings from a specific scan
ghost-sarif convert --scan-id SCAN_ID --output scan_findings.sarif

# List available scans
ghost-sarif list-scans

# List recent findings
ghost-sarif list-findings --limit 20

# Validate a SARIF file
ghost-sarif validate findings.sarif
```

### Python API Usage

```python
from ghost_sarif import GhostClient, GhostToSarifConverter

# Initialize client
client = GhostClient(api_key="your-api-key")

# Fetch findings
findings = client.get_all_findings()

# Convert to SARIF
converter = GhostToSarifConverter()
sarif_report = converter.convert_and_save(
    findings=findings,
    output_path="output.sarif",
    tool_name="Ghost Security",
    tool_version="1.0.0"
)

print(f"Converted {len(findings)} findings to SARIF format")
```

## Configuration

### API Key

Get your API key from the Ghost Security platform and use it in one of these ways:

1. **Command line parameter**: `--api-key YOUR_API_KEY`
2. **Environment variable**: `export GHOST_API_KEY=your-api-key`
3. **Configuration file**: Create a `.ghost-sarif.conf` file

### API Endpoint

By default, the client connects to `https://api.ghostsecurity.ai`. You can override this:

```bash
ghost-sarif convert --api-key YOUR_KEY --base-url https://your-ghost-instance.com
```

## SARIF Output Format

The converter generates SARIF 2.1.0 compliant reports with:

- **Rules**: Unique rules for each vulnerability type (CWE-based when available)
- **Results**: Individual findings with severity mapping
- **Locations**: File paths, line numbers, and code snippets
- **Metadata**: Ghost-specific properties and timestamps
- **Help Content**: Remediation guidance and reference links

### Severity Mapping

| Ghost Severity | SARIF Level |
|----------------|-------------|
| Critical       | error       |
| High           | error       |
| Medium         | warning     |
| Low            | warning     |
| Info           | info        |

## Sample Output

```json
{
  "$schema": "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/master/Schemata/sarif-schema-2.1.0.json",
  "version": "2.1.0",
  "runs": [
    {
      "tool": {
        "driver": {
          "name": "Ghost Security",
          "version": "1.0.0",
          "informationUri": "https://ghostsecurity.ai",
          "rules": [...]
        }
      },
      "results": [
        {
          "ruleId": "CWE-89",
          "level": "error",
          "message": {
            "text": "SQL Injection: SQL injection vulnerability in login form"
          },
          "locations": [
            {
              "physicalLocation": {
                "artifactLocation": {
                  "uri": "/src/auth/login.php"
                },
                "region": {
                  "startLine": 45,
                  "startColumn": 20,
                  "snippet": {
                    "text": "$query = \"SELECT * FROM users WHERE username = '\" . $_POST['username'] . \"'\";"
                  }
                }
              }
            }
          ]
        }
      ]
    }
  ]
}
```

## Development

### Setup Development Environment

```bash
git clone <repository-url>
cd Ghost-SARIF
pip install -r requirements.txt
pip install -e .
```

### Run Tests

```bash
# Run all tests
pytest

# Run with coverage
pytest --cov=ghost_sarif

# Run specific test file
pytest tests/test_converter.py -v
```

### Project Structure

```
Ghost-SARIF/
├── ghost_sarif/           # Main package
│   ├── __init__.py
│   ├── client.py          # Ghost API client
│   ├── converter.py       # SARIF converter
│   ├── models.py          # Data models
│   └── cli.py             # Command-line interface
├── tests/                 # Test suite
│   ├── test_client.py
│   └── test_converter.py
├── requirements.txt       # Dependencies
├── setup.py              # Package setup
└── README.md             # This file
```

## API Reference

### Ghost API Documentation

- **Base URL**: https://api.ghostsecurity.ai
- **Documentation**: https://docs.ghostsecurity.ai/api-reference
- **Authentication**: Bearer token (API key)

### Supported Endpoints

- `GET /v1/scans` - List scans
- `GET /v1/scans/{id}` - Get specific scan
- `GET /v1/findings` - List findings (with optional scan_id filter)

## Contributing

1. Fork the repository
2. Create a feature branch (`git checkout -b feature/amazing-feature`)
3. Make your changes
4. Add tests for new functionality
5. Run the test suite (`pytest`)
6. Commit your changes (`git commit -m 'Add amazing feature'`)
7. Push to the branch (`git push origin feature/amazing-feature`)
8. Open a Pull Request

## License

This project is licensed under the MIT License - see the LICENSE file for details.

## Support

- **Issues**: Report bugs and request features via GitHub Issues
- **Documentation**: https://docs.ghostsecurity.ai
- **Community**: Join our community discussions

## Changelog

### v1.0.0
- Initial release
- Ghost API client implementation
- SARIF 2.1.0 conversion support
- Command-line interface
- Comprehensive test suite
- Production-ready functionality
