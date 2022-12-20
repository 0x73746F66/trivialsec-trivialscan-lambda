import json
from os import path
from secrets import token_urlsafe
from typing import Union
from datetime import timedelta

from fastapi import Header, APIRouter, Response, File, UploadFile, status
from starlette.requests import Request
from cachier import cachier

import internals
import models
import config
import services.aws
import services.helpers

router = APIRouter()


@router.get(
    "/reports",
    response_model=list[models.ReportSummary],
    response_model_exclude_unset=True,
    response_model_exclude_none=True,
    status_code=status.HTTP_200_OK,
    responses={
        204: {"description": "No scan data is present for this account"},
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
    tags=["Scan Reports"],
)
@cachier(
    stale_after=timedelta(seconds=30),
    cache_dir=internals.CACHE_DIR,
    hash_params=lambda _, kw: services.helpers.parse_authorization_header(
        kw["authorization"]
    )["id"],
)
def retrieve_reports(
    request: Request,
    response: Response,
    authorization: Union[str, None] = Header(default=None),
):
    """
    Retrieves a collection of your own Trivial Scanner reports, providing a summary of each
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

    if scanner_record := models.ScannerRecord(account=authz.account).load():  # type: ignore
        return sorted(scanner_record.history, key=lambda x: x.date, reverse=True)  # type: ignore

    return Response(status_code=status.HTTP_204_NO_CONTENT)


@router.get(
    "/summary/{report_id}",
    response_model=models.ReportSummary,
    response_model_exclude_unset=True,
    response_model_exclude_none=True,
    status_code=status.HTTP_200_OK,
    responses={
        204: {"description": "No scan data is present for this account"},
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
    tags=["Scan Reports"],
)
@cachier(
    stale_after=timedelta(hours=1),
    cache_dir=internals.CACHE_DIR,
    hash_params=lambda _, kw: services.helpers.parse_authorization_header(
        kw["authorization"]
    )["id"]
    + kw.get("report_id"),
)
def retrieve_summary(
    request: Request,
    response: Response,
    report_id: str,
    authorization: Union[str, None] = Header(default=None),
):
    """
    Retrieves a summary of a Trivial Scanner report for the provided report identifier
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
    if scanner_record := models.ScannerRecord(account=authz.account).load():  # type: ignore
        for summary in scanner_record.history:
            if summary.report_id == report_id:
                return summary

    return Response(status_code=status.HTTP_204_NO_CONTENT)


@router.get(
    "/report/{report_id}",
    response_model=models.FullReport,
    response_model_exclude_unset=True,
    response_model_exclude_none=True,
    status_code=status.HTTP_200_OK,
    responses={
        204: {"description": "No scan data is present for this account"},
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
    tags=["Scan Reports"],
)
@cachier(
    stale_after=timedelta(minutes=15),
    cache_dir=internals.CACHE_DIR,
    hash_params=lambda _, kw: services.helpers.parse_authorization_header(
        kw["authorization"]
    )["id"]
    + str(kw.get("report_id"))
    + str(kw.get("full_certs"))
    + str(kw.get("full_hosts")),
)
def retrieve_full_report(
    request: Request,
    response: Response,
    report_id: str,
    authorization: Union[str, None] = Header(default=None),
):
    """
    Retrieves a full Trivial Scanner report for the provided report identiffier
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

    report = models.FullReport(report_id=report_id, account_name=authz.account.name).load()  # type: ignore
    if not report:
        return Response(status_code=status.HTTP_204_NO_CONTENT)

    report.evaluations = services.helpers.load_descriptions(report)
    scanner_record = models.ScannerRecord(account=authz.account).load()  # type: ignore
    for host in report.targets:  # type: ignore
        for target in scanner_record.monitored_targets:  # type: ignore
            if target.hostname == host.transport.hostname:
                host.monitoring_enabled = target.enabled

    return report


@router.get(
    "/certificate/{sha1_fingerprint}",
    response_model=models.Certificate,
    response_model_exclude_unset=True,
    response_model_exclude_none=True,
    status_code=status.HTTP_200_OK,
    responses={
        204: {"description": "No scan data is present for this account"},
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
    tags=["Scan Reports"],
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

        return json.loads(ret)

    except RuntimeError as err:
        response.status_code = status.HTTP_500_INTERNAL_SERVER_ERROR
        internals.logger.exception(err)


@router.post(
    "/store/{report_type}",
    status_code=status.HTTP_201_CREATED,
    responses={
        204: {"description": "No scan data is present for this account"},
        401: {
            "description": "Authorization Header was sent but something was not valid (check the logs), likely signed the wrong HTTP method or forgot to sign the base64 encoded POST data"
        },
        403: {
            "description": "Authorization Header was not sent, or dropped at a proxy (requesters issue) or the CDN (that one is our server misconfiguration)"
        },
        412: {
            "description": "When uploading a detailed report, the summary must first be sent"
        },
        500: {
            "description": "An unhandled error occurred during an AWS request for data access"
        },
    },
    tags=["Scan Reports"],
)
async def store(
    request: Request,
    response: Response,
    report_type: models.ReportType,
    files: list[UploadFile] = File(...),
    authorization: Union[str, None] = Header(default=None),
    x_trivialscan_account: Union[str, None] = Header(default=None),
    x_trivialscan_version: Union[str, None] = Header(default=None),
):
    """
    Stores various client report data generated by Trivial Scanner CLI
    """
    file = files[0]
    data = {}
    contents = await file.read()
    if not authorization:
        response.headers["WWW-Authenticate"] = internals.AUTHZ_REALM
        response.status_code = status.HTTP_403_FORBIDDEN
        return
    event = request.scope.get("aws.event", {})
    authz = internals.Authorization(
        request=request,
        user_agent=event.get("requestContext", {}).get("http", {}).get("userAgent"),
        ip_addr=event.get("requestContext", {}).get("http", {}).get("sourceIp"),
        account_name=x_trivialscan_account,
        raw_body=contents.decode("utf8"),
    )
    if not authz.is_valid:
        response.status_code = status.HTTP_401_UNAUTHORIZED
        response.headers["WWW-Authenticate"] = internals.AUTHZ_REALM
        return

    if file.filename.endswith(".json"):
        data: dict = json.loads(contents.decode("utf8"))
    if isinstance(data, dict):
        data["version"] = data.get("version", x_trivialscan_version)
        if "token" in data.get("config", {}):
            del data["config"]["token"]
        if "dashboard_api_url" in data.get("config", {}):
            del data["config"]["dashboard_api_url"]

    if report_type is models.ReportType.REPORT:
        data["report_id"] = token_urlsafe(56)
        data["results_uri"] = f'/result/{data["report_id"]}/detail'
        client_info = None
        if client := models.Client(account=authz.account, name=data.get("client_name")).load():  # type: ignore
            client_info = client.client_info
        report = models.ReportSummary(
            type=models.ScanRecordType.SELF_MANAGED,
            category=models.ScanRecordCategory.RECONNAISSANCE,
            is_passive=True,
            client=client_info,
            **data,
        )
        scanner_record = models.ScannerRecord(account=authz.account).load()  # type: ignore
        if not scanner_record:
            scanner_record = models.ScannerRecord(account=authz.account)  # type: ignore
        scanner_record.history.append(report)
        if scanner_record.save():
            return {"results_uri": data["results_uri"]}

    if report_type is models.ReportType.EVALUATIONS:
        full_report = models.FullReport(**data)
        if not full_report:
            response.status_code = status.HTTP_412_PRECONDITION_FAILED
            return
        if full_report.client_name:
            if client := models.Client(account=authz.account, name=full_report.client_name).load():  # type: ignore
                full_report.client = client.client_info
        items = []
        certs = {cert.sha1_fingerprint: cert for cert in full_report.certificates}  # type: ignore
        for _item in data["evaluations"]:
            item = models.EvaluationItem(
                generator=full_report.generator,
                version=full_report.version,
                account_name=authz.account.name,  # type: ignore
                client_name=full_report.client_name,
                report_id=full_report.report_id,
                observed_at=full_report.date,
                rule_id=_item["rule_id"],
                group=_item["group"],
                group_id=_item["group_id"],
                key=_item["key"],
                name=_item["name"],
                result_value=_item["result_value"],
                result_label=_item["result_label"],
                result_text=_item["result_text"],
                result_level=_item["result_level"],
                score=_item["score"],
                description=_item.get(
                    "description",
                    config.get_rule_desc(f"{_item['rule_id']}.{_item['group_id']}"),
                ),
                metadata=_item.get("metadata", {}),
                cve=_item.get("cve", []),
                cvss2=_item.get("cvss2"),
                cvss3=_item.get("cvss3"),
                references=[
                    models.ReferenceItem(name=ref["name"], url=ref["url"])
                    for ref in _item.get("references", []) or []
                ],
                compliance=[
                    models.ComplianceGroup(
                        compliance=comp["compliance"],
                        version=comp["version"],
                        items=[
                            models.ComplianceItem(**item)
                            for item in comp.get("items", [])
                        ],
                    )
                    for comp in _item["compliance"]
                ],
                threats=[
                    models.ThreatItem(**threat) for threat in _item.get("threats", [])
                ],
                transport=models.HostTransport(**_item["transport"]),
                certificate=certs.get(_item.get("metadata", {}).get("sha1_fingerprint"))
                if _item.get("group") == "certificate"
                else None,
            )
            items.append(item)

        full_report.evaluations = items
        if full_report.save():
            for cert in certs.values():
                cert.save()
            for host in full_report.targets:  # type: ignore
                host.save()
            return {"results_uri": f"/result/{full_report.report_id}/details"}

    if report_type is models.ReportType.CERTIFICATE and file.filename.endswith(".pem"):
        sha1_fingerprint = file.filename.replace(".pem", "")
        object_key = path.join(
            internals.APP_ENV, "certificates", f"{sha1_fingerprint}.pem"
        )
        if services.aws.store_s3(object_key, contents):  # type: ignore
            return {"results_uri": f"/certificate/{sha1_fingerprint}"}

    response.status_code = status.HTTP_500_INTERNAL_SERVER_ERROR


@router.delete(
    "/report/{report_id}",
    status_code=status.HTTP_202_ACCEPTED,
    responses={
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
    tags=["Scan Reports"],
)
async def delete_report(
    request: Request,
    response: Response,
    report_id: str,
    authorization: Union[str, None] = Header(default=None),
):
    """
    Deletes a specific ReportSummary within the ScannerRecord, the accompanying FullReport file, and eventually any aggregate evaluation records will be computed out also
    (as they are triggered from the deleted report file)
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

    if scanner_record := models.ScannerRecord(account=authz.account).load():  # type: ignore
        found = False
        history = []
        for summary in scanner_record.history:
            if summary.report_id == report_id:
                found = True
                continue
            history.append(summary)
        if found:
            scanner_record.history = history
            scanner_record.save()

    if report := models.FullReport(report_id=report_id, account_name=authz.account.name).load():  # type: ignore
        report.delete()
