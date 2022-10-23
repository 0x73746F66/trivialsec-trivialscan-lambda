import json
from os import path
from secrets import token_urlsafe
from typing import Union
from datetime import datetime, timedelta

from fastapi import Header, APIRouter, Response, File, UploadFile, status
from starlette.requests import Request

import internals
import models
import services.aws

router = APIRouter()

@router.get("/summary/{report_id}",
    response_model=models.ReportSummary,
    response_model_exclude_unset=True,
    response_model_exclude_none=True,
    status_code=status.HTTP_200_OK,
    tags=["Scan Reports"],
)
async def retrieve_summary(
    request: Request,
    response: Response,
    report_id: str,
    authorization: Union[str, None] = Header(default=None),
):
    """
    Retrieves a summary of a Trivial Scanner report for the provided report identiffier
    """
    if not authorization:
        response.headers['WWW-Authenticate'] = 'HMAC realm="Authorization Required"'
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
        response.headers['WWW-Authenticate'] = 'HMAC realm="Login Required"'
        return
    summary = models.ReportSummary(report_id=report_id, account_name=authz.account.name).load()  # type: ignore
    if not summary:
        response.status_code = status.HTTP_204_NO_CONTENT
        return
    return summary

@router.get("/report/{report_id}",
    response_model=models.FullReport,
    response_model_exclude_unset=True,
    response_model_exclude_none=True,
    status_code=status.HTTP_200_OK,
    tags=["Scan Reports"],
)
async def retrieve_report(
    request: Request,
    response: Response,
    report_id: str,
    authorization: Union[str, None] = Header(default=None),
):
    """
    Retrieves a full Trivial Scanner report for the provided report identiffier
    """
    if not authorization:
        response.headers['WWW-Authenticate'] = 'HMAC realm="Authorization Required"'
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
        response.headers['WWW-Authenticate'] = 'HMAC realm="Login Required"'
        return
    report = models.FullReport(report_id=report_id, account_name=authz.account.name).load()  # type: ignore
    if not report:
        response.status_code = status.HTTP_204_NO_CONTENT
        return

    return report

@router.get("/reports",
    response_model=list[models.ReportSummary],
    response_model_exclude_unset=True,
    response_model_exclude_none=True,
    status_code=status.HTTP_200_OK,
    tags=["Scan Reports"],
)
async def retrieve_reports(
    request: Request,
    response: Response,
    authorization: Union[str, None] = Header(default=None),
):
    """
    Retrieves a collection of your own Trivial Scanner reports, providing a summary of each
    """
    if not authorization:
        response.headers['WWW-Authenticate'] = 'HMAC realm="Authorization Required"'
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
        response.headers['WWW-Authenticate'] = 'HMAC realm="Login Required"'
        return

    summary_keys = []
    data = []
    prefix_key = path.join(internals.APP_ENV, "accounts", authz.account.name, "results")  # type: ignore
    try:
        summary_keys = services.aws.list_s3(prefix_key)

    except RuntimeError as err:
        response.status_code = status.HTTP_500_INTERNAL_SERVER_ERROR
        internals.logger.exception(err)
        return []

    if not summary_keys:
        response.status_code = status.HTTP_204_NO_CONTENT
        internals.logger.warning(f"No reports for {prefix_key}")
        return

    for summary_key in summary_keys:
        if not summary_key.endswith("summary.json"):
            continue
        ret = services.aws.get_s3(summary_key)
        if not ret:
            continue
        item = json.loads(ret)
        if item.get("config"):
            del item["config"]
        if item.get("flags"):
            del item["flags"]
        item["results_uri"] = f'/result/{summary_key.split("/")[-2]}/summary'
        data.append(item)

    if not data:
        response.status_code = status.HTTP_204_NO_CONTENT
        return

    return data

@router.get("/hosts",
    response_model=list[models.Host],
    response_model_exclude_unset=True,
    response_model_exclude_none=True,
    status_code=status.HTTP_200_OK,
    tags=["Scan Reports"],
)
async def retrieve_hosts(
    request: Request,
    response: Response,
    return_details: bool = False,
    authorization: Union[str, None] = Header(default=None),
):
    """
    Retrieves a collection of your own Trivial Scanner reports, providing
    a distinct list of hosts and ports, optionally returning the latest host
    full record
    """
    if not authorization:
        response.headers['WWW-Authenticate'] = 'HMAC realm="Authorization Required"'
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
        response.headers['WWW-Authenticate'] = 'HMAC realm="Login Required"'
        return

    path_keys = []
    data = []
    prefix_key = path.join(internals.APP_ENV, "accounts", authz.account.name, "results")  # type: ignore
    try:
        path_keys = services.aws.list_s3(prefix_key)

    except RuntimeError as err:
        response.status_code = status.HTTP_500_INTERNAL_SERVER_ERROR
        internals.logger.exception(err)
        return []

    if not path_keys:
        response.status_code = status.HTTP_204_NO_CONTENT
        internals.logger.warning(f"No reports for {prefix_key}")
        return

    seen = set()
    for object_key in path_keys:
        if not object_key.endswith("summary.json"):
            continue
        ret = services.aws.get_s3(object_key)
        if not ret:
            continue
        item = json.loads(ret)
        if not isinstance(item, dict):
            continue
        report = models.FullReport(**item)
        for target in report.targets or []:
            if target not in seen:
                seen.add(target)
                hostname, port = target.split(":")
                tspt = models.HostTransport(hostname=hostname, port=port)  # type: ignore
                host = models.Host(transport=tspt)  # type: ignore
                if return_details:
                    host.load()
                data.append(host)

    if not data:
        response.status_code = status.HTTP_204_NO_CONTENT
        return

    return data

@router.get("/host/{hostname}",
    response_model=models.Host,
    response_model_exclude_unset=True,
    response_model_exclude_none=True,
    status_code=status.HTTP_200_OK,
    tags=["Scan Reports"],
)
async def retrieve_host(
    request: Request,
    response: Response,
    hostname: str,
    port: int = 443,
    authorization: Union[str, None] = Header(default=None),
):
    """
    Retrieves TLS data on any hostname, providing an optional port number
    """
    if not authorization:
        response.headers['WWW-Authenticate'] = 'HMAC realm="Authorization Required"'
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
        response.headers['WWW-Authenticate'] = 'HMAC realm="Login Required"'
        return

    host_key = path.join(internals.APP_ENV, "hosts", hostname, str(port), "latest.json")
    try:
        ret = services.aws.get_s3(host_key)
        if not ret:
            response.status_code = status.HTTP_204_NO_CONTENT
            return

        return json.loads(ret)

    except RuntimeError as err:
        response.status_code = status.HTTP_500_INTERNAL_SERVER_ERROR
        internals.logger.exception(err)
        return err

@router.get("/certificate/{sha1_fingerprint}",
    response_model=models.Certificate,
    response_model_exclude_unset=True,
    response_model_exclude_none=True,
    status_code=status.HTTP_200_OK,
    tags=["Scan Reports"],
)
async def retrieve_certificate(
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
        response.headers['WWW-Authenticate'] = 'HMAC realm="Authorization Required"'
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
        response.headers['WWW-Authenticate'] = 'HMAC realm="Login Required"'
        return

    pem_key = path.join(internals.APP_ENV, "certificates", f"{sha1_fingerprint}.pem")
    cert_key = path.join(internals.APP_ENV, "certificates", f"{sha1_fingerprint}.json")
    try:
        ret = services.aws.get_s3(cert_key)
        if not ret:
            response.status_code = status.HTTP_204_NO_CONTENT
            return
        if include_pem:
            ret["pem"] = services.aws.get_s3(pem_key)

        return json.loads(ret)

    except RuntimeError as err:
        response.status_code = status.HTTP_500_INTERNAL_SERVER_ERROR
        internals.logger.exception(err)

@router.post("/store/{report_type}",
             status_code=status.HTTP_201_CREATED,
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
        response.headers['WWW-Authenticate'] = 'HMAC realm="Authorization Required"'
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
        response.headers['WWW-Authenticate'] = 'HMAC realm="Login Required"'
        return

    if file.filename.endswith(".json"):
        data: dict = json.loads(contents.decode("utf8"))
    if isinstance(data, dict):
        data["version"] = x_trivialscan_version
        if data.get("config", {}).get("token"):
            del data["config"]["token"]
        if data.get("config", {}).get("dashboard_api_url"):
            del data["config"]["dashboard_api_url"]

    if report_type is models.ReportType.REPORT:
        report_id = token_urlsafe(56)
        results_uri = f"/result/{report_id}/summary"
        report = models.ReportSummary(report_id=report_id, results_uri=results_uri, **data)
        if report.save():
            return {"results_uri": results_uri}

    if report_type is models.ReportType.EVALUATIONS:
        report_id = file.filename.replace(".json", "")
        _report = models.ReportSummary(report_id=report_id, account_name=authz.account.name).load()  # type: ignore
        if not _report:
            response.status_code = status.HTTP_412_PRECONDITION_FAILED
            return
        items = []
        for _item in data['evaluations']:
            item = models.EvaluationItem(
                generator=_report.generator,
                version=_report.version,
                account_name=authz.account.name,  # type: ignore
                client_name=_report.client_name,
                report_id=report_id,
                observed_at=_report.date,
                transport=models.HostTransport(**data['transport']),
                **_item,
            )
            if item.group == "certificate" and item.metadata.get("sha1_fingerprint"):
                item.certificate = models.Certificate(sha1_fingerprint=item.metadata.get("sha1_fingerprint")).load()  # type: ignore
            items.append(item)
        report = models.FullReport(**_report.dict())  # type: ignore
        report.evaluations = items
        if report.save():
            return {"results_uri": f"/result/{report_id}/details"}

    if report_type is models.ReportType.HOST:
        report = models.Host(**data)  # type: ignore
        if report.save():
            return {"results_uri": f"/host/{report.transport.hostname}/{report.transport.port}"}

    if report_type is models.ReportType.CERTIFICATE and file.filename.endswith(".json"):
        report = models.Certificate(**data)  # type: ignore
        if report.save():
            return {"results_uri": f"/certificate/{report.sha1_fingerprint}"}

    if report_type is models.ReportType.CERTIFICATE and file.filename.endswith(".pem"):
        sha1_fingerprint = file.filename.replace(".pem", "")
        object_key = path.join(internals.APP_ENV, "certificates", f"{sha1_fingerprint}.pem")
        if services.aws.store_s3(object_key, contents):  # type: ignore
            return {"results_uri": f"/certificate/{sha1_fingerprint}"}

    response.status_code = status.HTTP_500_INTERNAL_SERVER_ERROR
    return

@router.get("/findings/certificate",
    response_model=list[models.EvaluationItem],
    response_model_exclude_unset=True,
    response_model_exclude_none=True,
    status_code=status.HTTP_200_OK,
    tags=["Scan Reports"],
)
async def certificate_issues(
    request: Request,
    response: Response,
    limit: int = 20,
    authorization: Union[str, None] = Header(default=None),
):
    """
    Retrieves a collection of your own Trivial Scanner reports, providing
    a list of certificate issues filtered to include only the hightest risk
    and ordered by last seen
    """
    if not authorization:
        response.headers['WWW-Authenticate'] = 'HMAC realm="Authorization Required"'
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
        response.headers['WWW-Authenticate'] = 'HMAC realm="Login Required"'
        return

    path_keys = []
    full_data: list[models.EvaluationItem] = []
    prefix_key = path.join(internals.APP_ENV, "accounts", authz.account.name, "results")  # type: ignore
    try:
        path_keys = services.aws.list_s3(prefix_key)

    except RuntimeError as err:
        response.status_code = status.HTTP_500_INTERNAL_SERVER_ERROR
        internals.logger.exception(err)
        return []
    if not path_keys:
        response.status_code = status.HTTP_204_NO_CONTENT
        internals.logger.warning(f"No reports for {prefix_key}")
        return

    for object_key in path_keys:
        if not object_key.endswith("full-report.json"):
            continue
        ret = services.aws.get_s3(object_key)
        if not ret:
            continue
        d = json.loads(ret)
        if not isinstance(d, dict):
            continue
        report = models.FullReport(**d)
        for item in report.evaluations or []:
            if item.result_level == 'pass' or not item.certificate or item.group != "certificate":
                continue
            if not item.observed_at:
                item.observed_at = report.date
            full_data.append(item)

    if not full_data:
        response.status_code = status.HTTP_204_NO_CONTENT
        return

    priority_data: list[models.EvaluationItem] = sorted(full_data, key=lambda x: x.score)  # type: ignore
    uniq_data: list[models.EvaluationItem] = []
    seen = set()
    for item in priority_data:
        if item.key.startswith("trust_android_"):
            continue
        item: models.EvaluationItem
        key = item.rule_id if not item.key.startswith("trust_") else "trust"
        target = f"{item.certificate.sha1_fingerprint}{key}"  # type: ignore
        if target not in seen:
            uniq_data.append(item)
        seen.add(target)

    latest_data: list[models.EvaluationItem] = uniq_data[:limit]
    sorted_data = list(reversed(sorted(latest_data, key=lambda x: x.observed_at)))  # type: ignore

    return sorted_data

@router.get("/findings/latest",
    response_model=list[models.EvaluationItem],
    response_model_exclude_unset=True,
    response_model_exclude_none=True,
    status_code=status.HTTP_200_OK,
    tags=["Scan Reports"],
)
async def latest_findings(
    request: Request,
    response: Response,
    limit: int = 20,
    authorization: Union[str, None] = Header(default=None),
):
    """
    Retrieves a collection of your own Trivial Scanner reports, providing
    a list of host findings filtered to include only the hightest risk issues
    and ordered by last seen
    """
    if not authorization:
        response.headers['WWW-Authenticate'] = 'HMAC realm="Authorization Required"'
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
        response.headers['WWW-Authenticate'] = 'HMAC realm="Login Required"'
        return

    path_keys = []
    full_data: list[models.EvaluationItem] = []
    prefix_key = path.join(internals.APP_ENV, "accounts", authz.account.name, "results")  # type: ignore
    try:
        path_keys = services.aws.list_s3(prefix_key)

    except RuntimeError as err:
        response.status_code = status.HTTP_500_INTERNAL_SERVER_ERROR
        internals.logger.exception(err)
        return []

    if not path_keys:
        response.status_code = status.HTTP_204_NO_CONTENT
        internals.logger.warning(f"No reports for {prefix_key}")
        return

    for object_key in path_keys:
        if not object_key.endswith("full-report.json"):
            continue
        ret = services.aws.get_s3(object_key)
        if not ret:
            continue
        d = json.loads(ret)
        if not isinstance(d, dict):
            continue
        report = models.FullReport(**d)
        for item in report.evaluations or []:
            if item.result_level == 'pass' or not item.transport or item.group == "certificate":
                continue
            if not item.observed_at:
                item.observed_at = report.date
            full_data.append(item)

    if not full_data:
        response.status_code = status.HTTP_204_NO_CONTENT
        return

    priority_data: list[models.EvaluationItem] = sorted(full_data, key=lambda x: x.score)  # type: ignore
    uniq_data: list[models.EvaluationItem] = []
    seen = set()
    for item in priority_data:
        target = f"{item.transport.hostname}{item.transport.port}{item.transport.peer_address}{item.rule_id}"  # type: ignore
        if target not in seen:
            uniq_data.append(item)
        seen.add(target)

    latest_data: list[models.EvaluationItem] = uniq_data[:limit]
    sorted_data = list(reversed(sorted(latest_data, key=lambda x: x.observed_at)))  # type: ignore

    return sorted_data
