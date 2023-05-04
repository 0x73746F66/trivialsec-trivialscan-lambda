import logging
from os import getenv

from fastapi import FastAPI
from fastapi.middleware.gzip import GZipMiddleware
from fastapi.middleware.cors import CORSMiddleware
from mangum import Mangum
from lumigo_tracer import lumigo_tracer

import internals
import services.aws
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
    title="Trivial Scanner Dashboard OpenAPI",
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


@lumigo_tracer(
    token=services.aws.get_ssm(
        f"/{internals.APP_ENV}/{internals.APP_NAME}/Lumigo/token", WithDecryption=True
    ),
    should_report=internals.APP_ENV == "Prod",
    skip_collecting_http_body=True,
    verbose=getenv("AWS_EXECUTION_ENV") is None,
)
def handler(event, context):
    execution_tags = {}
    if event.get("path"):
        execution_tags["path"] = event["rawPath"]
    elif event.get("rawPath"):
        execution_tags["path"] = event["rawPath"]
    if event.get("http", {}).get("method"):
        execution_tags["method"] = event["http"]["method"]
    elif event.get("httpMethod"):
        execution_tags["httpMethod"] = event["httpMethod"]
    if event.get("http", {}).get("protocol"):
        execution_tags["protocol"] = event["http"]["protocol"]
    if event.get("http", {}).get("sourceIp"):
        execution_tags["sourceIp"] = event["http"]["sourceIp"]
    if execution_tags:
        internals.trace_tag(execution_tags)
    asgi_handler = Mangum(app, lifespan="off")
    return asgi_handler(event, context)
