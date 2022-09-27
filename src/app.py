import logging
from os import getenv

from fastapi import FastAPI
from fastapi.middleware.gzip import GZipMiddleware
from mangum import Mangum

import utils
import router

DEFAULT_LOG_LEVEL = "WARNING"
LOG_LEVEL = getenv("LOG_LEVEL", DEFAULT_LOG_LEVEL)

app = FastAPI(
    title="Trivial Scanner Dashboard API",
)
app.add_middleware(GZipMiddleware, minimum_size=1000)
app.include_router(router.router)

@app.on_event("startup")
async def startup_event():
    if getenv("AWS_EXECUTION_ENV") is None:
        utils.logger = logging.getLogger("uvicorn.default")
    utils.logger.setLevel(getattr(logging, LOG_LEVEL, DEFAULT_LOG_LEVEL))

handler = Mangum(app, lifespan="off")
