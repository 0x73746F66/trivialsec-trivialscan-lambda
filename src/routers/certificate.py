import json
from os import path
from typing import Union
from datetime import timedelta

from fastapi import Header, APIRouter, Response, status
from starlette.requests import Request
from cachier import cachier

import internals
import models
import services.aws
import services.helpers

router = APIRouter()


@router.get(
    "/{sha1_fingerprint}",
    response_model=models.CertificateResponse,
    response_model_exclude_unset=True,
    response_model_exclude_none=True,
    status_code=status.HTTP_200_OK,
    responses={
        204: {"description": "No Certificate using this SHA1 fingerprint found in our scan data"},
        401: {
            "description": "Authorization Header was sent but something was not valid (check the logs), likely signed the wrong HTTP method or forgot to sign the base64 encoded POST data"
        },
        403: {
            "description": "Authorization Header was not sent, or dropped at a proxy (requesters issue) or the CDN (that one is our server misconfiguration)"
        },
        500: {
            "description": "An unhandled error occurred during an AWS request for data access"
        },
    },
    tags=["Certificates"],
)
@cachier(
    stale_after=timedelta(seconds=30),
    cache_dir=internals.CACHE_DIR,
    hash_params=lambda _, kw: services.helpers.parse_authorization_header(
        kw["authorization"]
    )["id"]
    + kw.get("sha1_fingerprint")
    + str(kw.get("include_pem")),
)
def retrieve_certificate(
    request: Request,
    response: Response,
    sha1_fingerprint: str,
    include_pem: bool = False,
    authorization: Union[str, None] = Header(default=None),
):
    """
    Retrieves TLS Certificate data by SHA1 fingerprint, optionally provides the PEM encoded certificate
    """
    if not authorization:
        response.headers["WWW-Authenticate"] = internals.AUTHZ_REALM
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
        response.headers["WWW-Authenticate"] = internals.AUTHZ_REALM
        return

    pem_key = path.join(internals.APP_ENV, "certificates", f"{sha1_fingerprint}.pem")
    cert_key = path.join(internals.APP_ENV, "certificates", f"{sha1_fingerprint}.json")
    try:
        ret = services.aws.get_s3(path_key=cert_key)
        if not ret:
            return Response(status_code=status.HTTP_204_NO_CONTENT)
        if include_pem:
            ret["pem"] = services.aws.get_s3(path_key=pem_key)

        certificate = models.Certificate(**json.loads(ret))
        reports = []
        if scanner_record := models.ScannerRecord(account=authz.account).load():  # type: ignore
            for record in scanner_record.history:
                for cert in record.certificates:  # type: ignore
                    if cert.sha1_fingerprint == sha1_fingerprint:
                        reports.append(record)

        return models.CertificateResponse(certificate=certificate, reports=sorted(reports, key=lambda x: x.date, reverse=True))  # type: ignore

    except RuntimeError as err:
        response.status_code = status.HTTP_500_INTERNAL_SERVER_ERROR
        internals.logger.exception(err)
