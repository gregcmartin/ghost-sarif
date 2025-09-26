"""Ghost SARIF API Client - Convert Ghost security findings to SARIF format."""

__version__ = "1.0.0"
__author__ = "Ghost SARIF Client"
__description__ = "API client to Ghost Application security platform that converts vulnerability findings to SARIF output"

from .client import GhostClient
from .converter import GhostToSarifConverter
from .models import *

__all__ = [
    "GhostClient",
    "GhostToSarifConverter",
]
