import logging
from os import getenv

from fastapi import FastAPI
from fastapi.middleware.gzip import GZipMiddleware
from fastapi.middleware.cors import CORSMiddleware
from mangum import Mangum
import boto3

import internals
from routers import account, member, report, dashboard, stripe

DEFAULT_LOG_LEVEL = "WARNING"
LOG_LEVEL = getenv("LOG_LEVEL", DEFAULT_LOG_LEVEL)

app = FastAPI(
    title="Trivial Scanner Dashboard API",
)
app.add_middleware(GZipMiddleware, minimum_size=1000)
app.add_middleware(
    CORSMiddleware,
    allow_origins=internals.ALLOWED_ORIGINS,
    allow_credentials=True,
    allow_methods=["POST", "GET", "DELETE"],
    allow_headers=[
        "X-Trivialscan-Account",
        "X-Trivialscan-Version",
        "Authorization",
    ],
    max_age=3600,
)
app.include_router(account.router)
app.include_router(member.router)
app.include_router(report.router)
app.include_router(stripe.router)
app.include_router(dashboard.router)

@app.on_event("startup")
async def startup_event():
    if getenv("AWS_EXECUTION_ENV") is None:
        internals.logger = logging.getLogger("uvicorn.default")
    boto3.set_stream_logger('boto3', getattr(logging, LOG_LEVEL, DEFAULT_LOG_LEVEL))  # type: ignore
    internals.logger.setLevel(getattr(logging, LOG_LEVEL, DEFAULT_LOG_LEVEL))

handler = Mangum(app, lifespan="off")
