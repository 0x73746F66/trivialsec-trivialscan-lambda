import logging
from os import getenv

from fastapi import FastAPI
from fastapi.middleware.gzip import GZipMiddleware
from fastapi.middleware.cors import CORSMiddleware
from mangum import Mangum

import internals
from routers import (
    account,
    member,
    report,
    host,
    certificate,
    dashboard,
    stripe,
    scanner,
    search,
    client,
    sendgrid,
)

app = FastAPI(
    title="Trivial Scanner Dashboard API",
)
if getenv("AWS_EXECUTION_ENV"):
    from fastapi.middleware.httpsredirect import (
        HTTPSRedirectMiddleware,
    )  # pylint: disable=ungrouped-imports

    app.add_middleware(HTTPSRedirectMiddleware)
app.add_middleware(GZipMiddleware, minimum_size=1000)
app.add_middleware(
    CORSMiddleware,
    allow_origins=internals.ALLOWED_ORIGINS,
    allow_credentials=True,
    allow_methods=["POST", "GET", "DELETE"],
    allow_headers=[
        "Origin",
        "User-Agent",
        "X-Trivialscan-Account",
        "X-Trivialscan-Version",
        "X-Forwarded-For",
        "X-Real-IP",
        "Authorization",
    ],
    max_age=3600,
)
app.include_router(account.router)
app.include_router(member.router)
app.include_router(report.router)
app.include_router(host.router)
app.include_router(certificate.router, prefix="/certificate")
app.include_router(dashboard.router)
app.include_router(scanner.router, prefix="/scanner")
app.include_router(search.router, prefix="/search")
app.include_router(client.router)
app.include_router(sendgrid.router, include_in_schema=False, prefix="/sendgrid")
app.include_router(stripe.router, include_in_schema=False, prefix="/stripe")


@app.on_event("startup")
async def startup_event():
    if getenv("AWS_EXECUTION_ENV") is None:
        internals.logger = logging.getLogger("uvicorn.default")


handler = Mangum(app, lifespan="off")
