"""
Centralized error handling module for ChatSpic.

Implements safe, consistent exception handling for FastAPI HTTP endpoints:
- Intentional client errors (4xx) preserve original status codes, safe details, and headers.
- Unexpected server exceptions return generic HTTP 500 without leaking tracebacks,
  database details, SQL queries, or filesystem paths.
- Server-side logging of unexpected exceptions with complete traceback context.
"""
import logging
from fastapi import FastAPI, Request, status
from fastapi.exceptions import RequestValidationError
from fastapi.responses import JSONResponse
from starlette.exceptions import HTTPException as StarletteHTTPException

from backend.services.chat_service import (
    NotFoundError as ChatNotFoundError,
    BadRequestError as ChatBadRequestError,
    ForbiddenError as ChatForbiddenError,
)
from backend.services.reaction_service import (
    NotFoundError as ReactionNotFoundError,
    BadRequestError as ReactionBadRequestError,
)

logger = logging.getLogger(__name__)


def register_exception_handlers(app: FastAPI) -> None:
    """Register centralized exception handlers on the FastAPI application."""

    @app.exception_handler(StarletteHTTPException)
    async def http_exception_handler(request: Request, exc: StarletteHTTPException):
        """Handle standard HTTPExceptions.

        Client errors (< 500) preserve their status code, detail, and headers.
        Server errors (>= 500) are logged with traceback and masked with a generic message.
        """
        if exc.status_code >= 500:
            logger.error(
                "Server error during HTTP %s %s (status %s): %s",
                request.method,
                request.url.path,
                exc.status_code,
                exc.detail,
                exc_info=True,
            )
            return JSONResponse(
                status_code=500,
                content={"detail": "Internal server error"},
                headers=exc.headers,
            )

        return JSONResponse(
            status_code=exc.status_code,
            content={"detail": exc.detail},
            headers=exc.headers,
        )

    @app.exception_handler(RequestValidationError)
    async def validation_exception_handler(request: Request, exc: RequestValidationError):
        """Handle request schema validation errors, returning safe 422 payload."""
        return JSONResponse(
            status_code=422,
            content={"detail": exc.errors()},
        )

    @app.exception_handler(ChatNotFoundError)
    @app.exception_handler(ReactionNotFoundError)
    async def not_found_exception_handler(request: Request, exc: Exception):
        """Translate service-level NotFoundError to HTTP 404."""
        return JSONResponse(
            status_code=status.HTTP_404_NOT_FOUND,
            content={"detail": str(exc)},
        )

    @app.exception_handler(ChatBadRequestError)
    @app.exception_handler(ReactionBadRequestError)
    async def bad_request_exception_handler(request: Request, exc: Exception):
        """Translate service-level BadRequestError to HTTP 400."""
        return JSONResponse(
            status_code=status.HTTP_400_BAD_REQUEST,
            content={"detail": str(exc)},
        )

    @app.exception_handler(ChatForbiddenError)
    async def forbidden_exception_handler(request: Request, exc: Exception):
        """Translate service-level ForbiddenError to HTTP 403."""
        return JSONResponse(
            status_code=status.HTTP_403_FORBIDDEN,
            content={"detail": str(exc)},
        )

    @app.exception_handler(Exception)
    async def unhandled_exception_handler(request: Request, exc: Exception):
        """Catch-all for unexpected server exceptions.

        Logs full traceback and request context server-side while returning
        a generic HTTP 500 response to clients.
        """
        logger.error(
            "Unhandled server exception during HTTP %s %s: %s",
            request.method,
            request.url.path,
            str(exc),
            exc_info=True,
        )
        return JSONResponse(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            content={"detail": "Internal server error"},
        )
