class SentinelError(Exception):
    """Base exception for all Sentinel errors."""
    def __init__(self, message: str, details: dict = None):
        super().__init__(message)
        self.message = message
        self.details = details or {}

class ToolExecutionError(SentinelError):
    """Raised when a security tool fails to execute or returns an error."""
    pass

class ConfigError(SentinelError):
    """Raised when configuration is missing or invalid."""
    pass

class ValidationError(SentinelError):
    """Raised when input validation fails."""
    pass
