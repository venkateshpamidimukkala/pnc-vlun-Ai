from fastapi import Request
from fastapi.responses import JSONResponse
from sqlalchemy.exc import IntegrityError


def register_exception_handlers(app):
    @app.exception_handler(IntegrityError)
    async def integrity_error(_: Request, __: IntegrityError):
        return JSONResponse(status_code=409, content={"code": "CONFLICT", "detail": "Resource conflicts with existing data"})

    @app.exception_handler(Exception)
    async def unhandled_error(_: Request, __: Exception):
        return JSONResponse(status_code=500, content={"code": "INTERNAL_ERROR", "detail": "Internal server error"})
