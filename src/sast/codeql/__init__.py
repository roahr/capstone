"""CodeQL integration for the SEC-C SAST engine."""

from src.sast.codeql.database_manager import CodeQLDatabaseManager
from src.sast.codeql.query_executor import CodeQLQueryExecutor

__all__ = ["CodeQLDatabaseManager", "CodeQLQueryExecutor"]
