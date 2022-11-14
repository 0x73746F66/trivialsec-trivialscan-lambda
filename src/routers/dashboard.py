import json
from typing import Union
from datetime import timedelta

from fastapi import Header, APIRouter, Response, status
from starlette.requests import Request
from cachier import cachier

import internals
import models
import services.sendgrid
import services.stripe
import services.aws
import services.helpers

router = APIRouter()


@router.get("/dashboard/compliance",
    response_model=list[models.DashboardCompliance],
    response_model_exclude_unset=True,
    response_model_exclude_none=True,
    status_code=status.HTTP_200_OK,
    responses={
        204: {"description": "No scan data is present for this account"},
        401: {"description": "Authorization Header was sent but something was not valid (check the logs), likely signed the wrong HTTP method or forgot to sign the base64 encoded POST data"},
        403: {"description": "Authorization Header was not sent, or dropped at a proxy (requesters issue) or the CDN (that one is our server misconfiguration)"},
        500: {"description": "An unhandled error occured during an AWS request for data access"},
    },
    tags=["Dashboard"],
)
@cachier(
    stale_after=timedelta(minutes=5),
    cache_dir=internals.CACHE_DIR,
    hash_params=lambda _, kw: services.helpers.parse_authorization_header(kw["authorization"])["id"]
)
def dashboard_compliance(
    request: Request,
    response: Response,
    authorization: Union[str, None] = Header(default=None),
):
    """
    Retrieves a collection of your clients
    """
    if not authorization:
        response.headers['WWW-Authenticate'] = 'HMAC realm="trivialscan"'
        response.status_code = status.HTTP_403_FORBIDDEN
        return
    event = request.scope.get("aws.event", {})
    authz = internals.Authorization(
        request=request,
        user_agent=event.get("requestContext", {}).get("http", {}).get("userAgent"),
        ip_addr=event.get("requestContext", {}).get("http", {}).get("sourceIp"),
    )
    if not authz.is_valid:
        response.status_code = status.HTTP_401_UNAUTHORIZED
        response.headers['WWW-Authenticate'] = 'HMAC realm="trivialscan"'
        return

    object_key = f"{internals.APP_ENV}/accounts/{authz.account.name}/computed/dashboard-compliance.json"  # type: ignore
    try:
        raw = services.aws.get_s3(path_key=object_key)
        if not raw:
            return Response(status_code=status.HTTP_204_NO_CONTENT)
        data = json.loads(raw)
        for item in data:
            try:
                item['label'] = getattr(models.GraphLabel, item['label'])
            except AttributeError:
                pass  # Label should already be the correct value

        return data


    except RuntimeError as err:
        internals.logger.exception(err)
    response.status_code = status.HTTP_500_INTERNAL_SERVER_ERROR
    return


@router.get("/dashboard/quotas",
    response_model=models.AccountQuotas,
    response_model_exclude_unset=True,
    response_model_exclude_none=True,
    status_code=status.HTTP_200_OK,
    responses={
        401: {"description": "Authorization Header was sent but something was not valid (check the logs), likely signed the wrong HTTP method or forgot to sign the base64 encoded POST data"},
        403: {"description": "Authorization Header was not sent, or dropped at a proxy (requesters issue) or the CDN (that one is our server misconfiguration)"},
        500: {"description": "An unhandled error occured during an AWS request for data access"},
    },
    tags=["Dashboard"],
)
@cachier(
    stale_after=timedelta(seconds=30),
    cache_dir=internals.CACHE_DIR,
    hash_params=lambda _, kw: services.helpers.parse_authorization_header(kw["authorization"])["id"]
)
def dashboard_quotas(
    request: Request,
    response: Response,
    authorization: Union[str, None] = Header(default=None),
):
    """
    Retrieves a collection of your clients
    """
    if not authorization:
        response.headers['WWW-Authenticate'] = 'HMAC realm="trivialscan"'
        response.status_code = status.HTTP_403_FORBIDDEN
        return
    event = request.scope.get("aws.event", {})
    authz = internals.Authorization(
        request=request,
        user_agent=event.get("requestContext", {}).get(
            "http", {}).get("userAgent"),
        ip_addr=event.get("requestContext", {}).get(
            "http", {}).get("sourceIp"),
    )
    if not authz.is_valid:
        response.status_code = status.HTTP_401_UNAUTHORIZED
        response.headers['WWW-Authenticate'] = 'HMAC realm="trivialscan"'
        return

    return services.helpers.get_quotas(authz.account)  # type: ignore
