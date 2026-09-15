from typing import Any


class APIException(Exception):
    """Base exception for all application-level errors."""
    def __init__(
        self,
        message: str,
        status_code: int = 400,
        error_code: str = "BAD_REQUEST",
        details: dict[str, Any] | None = None
    ):
        self.message = message
        self.status_code = status_code
        self.error_code = error_code
        self.details = details or {}
        super().__init__(self.message)

class UnauthorizedException(APIException):
    def __init__(self, message: str = "Unauthorized"):
        super().__init__(message, status_code=401, error_code="UNAUTHORIZED")

class ForbiddenException(APIException):
    def __init__(self, message: str = "Forbidden"):
        super().__init__(message, status_code=403, error_code="FORBIDDEN")

class NotFoundException(APIException):
    def __init__(self, message: str = "Resource not found"):
        super().__init__(message, status_code=404, error_code="NOT_FOUND")

class ValidationException(APIException):
    def __init__(self, message: str = "Validation error", details: dict[str, Any] | None = None):
        super().__init__(message, status_code=422, error_code="VALIDATION_ERROR", details=details)


class InvalidTargetUrlException(APIException):
    def __init__(self, message: str = "Assessment target must be a concrete HTTP/HTTPS URL.", details: dict[str, Any] | None = None):
        super().__init__(message, status_code=400, error_code="INVALID_TARGET_URL", details=details)


class WildcardTargetException(APIException):
    def __init__(self, message: str = "Wildcard scope rules cannot be used as executable assessment targets. Enter a concrete host.", details: dict[str, Any] | None = None):
        super().__init__(message, status_code=400, error_code="WILDCARD_TARGET_NOT_ALLOWED", details=details)


class OutOfScopeException(APIException):
    def __init__(self, message: str = "Target is not authorized by the selected scope program.", details: dict[str, Any] | None = None):
        super().__init__(message, status_code=400, error_code="OUT_OF_SCOPE", details=details)


class AuthorizationRequiredException(APIException):
    def __init__(self, message: str = "Explicit operator authorization is required before launch.", details: dict[str, Any] | None = None):
        super().__init__(message, status_code=400, error_code="AUTHORIZATION_REQUIRED", details=details)

