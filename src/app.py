import logging
from os import getenv

from fastapi import FastAPI
from fastapi.middleware.gzip import GZipMiddleware
from fastapi.middleware.cors import CORSMiddleware
from mangum import Mangum

import utils
import router

DEFAULT_LOG_LEVEL = "WARNING"
LOG_LEVEL = getenv("LOG_LEVEL", DEFAULT_LOG_LEVEL)
origins = [
    "https://www.trivialsec.com",
    "https://scanner.trivialsec.com",
    "http://jager:5173",
    "http://localhost:5173",
]

app = FastAPI(
    title="Trivial Scanner Dashboard API",
)
app.add_middleware(GZipMiddleware, minimum_size=1000)
app.add_middleware(
    CORSMiddleware,
    allow_origins=origins,
    allow_credentials=True,
    allow_methods=["POST", "GET", "DELETE"],
    allow_headers=[
        "X-Trivialscan-Account",
        "X-Trivialscan-Version",
        "Authorization",
    ],
    max_age=3600,
)
app.include_router(router.router)

@app.on_event("startup")
async def startup_event():
    if getenv("AWS_EXECUTION_ENV") is None:
        utils.logger = logging.getLogger("uvicorn.default")
    utils.logger.setLevel(getattr(logging, LOG_LEVEL, DEFAULT_LOG_LEVEL))

handler = Mangum(app, lifespan="off")
