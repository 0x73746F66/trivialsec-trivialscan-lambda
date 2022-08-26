import logging

from fastapi import FastAPI
from fastapi.middleware.gzip import GZipMiddleware
from mangum import Mangum

import utils
import router

logger = logging.getLogger(__name__)
logger.setLevel(logging.INFO)

app = FastAPI(
    title="Trivial Scanner Dashboard API",
    version=utils.__trivialscan_version__,
)
app.add_middleware(GZipMiddleware, minimum_size=1000)
app.include_router(router.router, prefix=f"/{utils.__trivialscan_version__}")
handler = Mangum(app, lifespan="off")
