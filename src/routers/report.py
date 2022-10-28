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
import services.aws
import services.helpers

router = APIRouter()


@router.get("/summary/{report_id}",
    response_model=models.ReportSummary,
    response_model_exclude_unset=True,
    response_model_exclude_none=True,
    status_code=status.HTTP_200_OK,
    responses={
        204: {"description": "No scan data is present for this account"},
        401: {"description": "Authorization Header was sent but something was not valid (check the logs), likely signed the wrong HTTP method or forgot to sign the base64 encoded POST data"},
        403: {"description": "Authorization Header was not sent, or dropped at a proxy (requesters issue) or the CDN (that one is our server misconfiguration)"},
        500: {"description": "An unhandled error occured during an AWS request for data access"},
    },
    tags=["Scan Reports"],
)
@cachier(
    stale_after=timedelta(hours=1),
    cache_dir=internals.CACHE_DIR,
    hash_params=lambda _, kw: services.helpers.parse_authorization_header(kw["authorization"])["id"]+kw.get("report_id")
)
def retrieve_summary(
    request: Request,
    response: Response,
    report_id: str,
    authorization: Union[str, None] = Header(default=None),
):
    """
    Retrieves a summary of a Trivial Scanner report for the provided report identiffier
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
    summary = models.ReportSummary(report_id=report_id, account_name=authz.account.name).load()  # type: ignore
    if not summary:
        return Response(status_code=status.HTTP_204_NO_CONTENT)
    return summary


@router.get("/report/{report_id}",
    response_model=models.FullReport,
    response_model_exclude_unset=True,
    response_model_exclude_none=True,
    status_code=status.HTTP_200_OK,
    responses={
        204: {"description": "No scan data is present for this account"},
        401: {"description": "Authorization Header was sent but something was not valid (check the logs), likely signed the wrong HTTP method or forgot to sign the base64 encoded POST data"},
        403: {"description": "Authorization Header was not sent, or dropped at a proxy (requesters issue) or the CDN (that one is our server misconfiguration)"},
        500: {"description": "An unhandled error occured during an AWS request for data access"},
    },
    tags=["Scan Reports"],
)
@cachier(
    stale_after=timedelta(hours=1),
    cache_dir=internals.CACHE_DIR,
    hash_params=lambda _, kw: services.helpers.parse_authorization_header(kw["authorization"])["id"]+kw.get("report_id")
)
def retrieve_report(
    request: Request,
    response: Response,
    report_id: str,
    authorization: Union[str, None] = Header(default=None),
):
    """
    Retrieves a full Trivial Scanner report for the provided report identiffier
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
    report = models.FullReport(report_id=report_id, account_name=authz.account.name).load()  # type: ignore
    if not report:
        return Response(status_code=status.HTTP_204_NO_CONTENT)

    return report


@router.get("/reports",
    response_model=list[models.ReportSummary],
    response_model_exclude_unset=True,
    response_model_exclude_none=True,
    status_code=status.HTTP_200_OK,
    responses={
        204: {"description": "No scan data is present for this account"},
        401: {"description": "Authorization Header was sent but something was not valid (check the logs), likely signed the wrong HTTP method or forgot to sign the base64 encoded POST data"},
        403: {"description": "Authorization Header was not sent, or dropped at a proxy (requesters issue) or the CDN (that one is our server misconfiguration)"},
        500: {"description": "An unhandled error occured during an AWS request for data access"},
    },
    tags=["Scan Reports"],
)
@cachier(
    stale_after=timedelta(seconds=30),
    cache_dir=internals.CACHE_DIR,
    hash_params=lambda _, kw: services.helpers.parse_authorization_header(kw["authorization"])["id"]
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
        internals.logger.warning(f"No reports for {prefix_key}")
        return Response(status_code=status.HTTP_204_NO_CONTENT)

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
        return Response(status_code=status.HTTP_204_NO_CONTENT)

    return data


@router.get("/certificate/{sha1_fingerprint}",
    response_model=models.Certificate,
    response_model_exclude_unset=True,
    response_model_exclude_none=True,
    status_code=status.HTTP_200_OK,
    responses={
        204: {"description": "No scan data is present for this account"},
        401: {"description": "Authorization Header was sent but something was not valid (check the logs), likely signed the wrong HTTP method or forgot to sign the base64 encoded POST data"},
        403: {"description": "Authorization Header was not sent, or dropped at a proxy (requesters issue) or the CDN (that one is our server misconfiguration)"},
        500: {"description": "An unhandled error occured during an AWS request for data access"},
    },
    tags=["Scan Reports"],
)
@cachier(
    stale_after=timedelta(seconds=30),
    cache_dir=internals.CACHE_DIR,
    hash_params=lambda _, kw: services.helpers.parse_authorization_header(kw["authorization"])["id"]+kw.get("sha1_fingerprint")+str(kw.get("include_pem"))
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

    pem_key = path.join(internals.APP_ENV, "certificates", f"{sha1_fingerprint}.pem")
    cert_key = path.join(internals.APP_ENV, "certificates", f"{sha1_fingerprint}.json")
    try:
        ret = services.aws.get_s3(cert_key)
        if not ret:
            return Response(status_code=status.HTTP_204_NO_CONTENT)
        if include_pem:
            ret["pem"] = services.aws.get_s3(pem_key)

        return json.loads(ret)

    except RuntimeError as err:
        response.status_code = status.HTTP_500_INTERNAL_SERVER_ERROR
        internals.logger.exception(err)

@router.post("/store/{report_type}",
    status_code=status.HTTP_201_CREATED,
    responses={
        204: {"description": "No scan data is present for this account"},
        401: {"description": "Authorization Header was sent but something was not valid (check the logs), likely signed the wrong HTTP method or forgot to sign the base64 encoded POST data"},
        403: {"description": "Authorization Header was not sent, or dropped at a proxy (requesters issue) or the CDN (that one is our server misconfiguration)"},
        412: {"description": "When uploading a detailed report, the summary must first be sent"},
        500: {"description": "An unhandled error occured during an AWS request for data access"},
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
        response.headers['WWW-Authenticate'] = 'HMAC realm="trivialscan"'
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
        response.headers['WWW-Authenticate'] = 'HMAC realm="trivialscan"'
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
        # report.date = datetime.utcnow() - timedelta(days=27)
        if report.save():
            scans_map: dict[str, dict[str, list[str]]] = {}
            object_key = f"{internals.APP_ENV}/accounts/{authz.account.name}/scan-history.json"  # type: ignore
            if history_raw := services.aws.get_s3(object_key):
                scans_map: dict[str, dict[str, list[str]]] = json.loads(history_raw)
            for target in report.targets or []:
                scans_map.setdefault(target, {'reports': []})
                scans_map[target]['reports'].append(report.report_id)
            services.aws.store_s3(object_key, json.dumps(scans_map, default=str))
            return {"results_uri": results_uri}

    if report_type is models.ReportType.EVALUATIONS:
        report_id = file.filename.replace(".json", "")
        _report = models.ReportSummary(report_id=report_id, account_name=authz.account.name).load()  # type: ignore
        if not _report:
            response.status_code = status.HTTP_412_PRECONDITION_FAILED
            return
        items = []
        certs = {}
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
                if item.metadata.get("sha1_fingerprint") not in certs:
                    certs[item.metadata.get("sha1_fingerprint")] = models.Certificate(sha1_fingerprint=item.metadata.get("sha1_fingerprint")).load()  # type: ignore
                item.certificate = certs[item.metadata.get("sha1_fingerprint")]
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
    responses={
        204: {"description": "No scan data is present for this account"},
        401: {"description": "Authorization Header was sent but something was not valid (check the logs), likely signed the wrong HTTP method or forgot to sign the base64 encoded POST data"},
        403: {"description": "Authorization Header was not sent, or dropped at a proxy (requesters issue) or the CDN (that one is our server misconfiguration)"},
        500: {"description": "An unhandled error occured during an AWS request for data access"},
    },
    tags=["Scan Reports"],
)
@cachier(
    stale_after=timedelta(minutes=5),
    cache_dir=internals.CACHE_DIR,
    hash_params=lambda _, kw: services.helpers.parse_authorization_header(kw["authorization"])["id"]+str(kw.get("limit"))
    )
def certificate_issues(
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
        internals.logger.warning(f"No reports for {prefix_key}")
        return Response(status_code=status.HTTP_204_NO_CONTENT)

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
            if item.cvss2:
                item.references.append(models.ReferenceItem(name=f"CVSSv2 {item.cvss2}", url=f"https://nvd.nist.gov/vuln-metrics/cvss/v2-calculator?vector=({item.cvss2})"))  # type: ignore
            if item.cvss3:
                item.references.append(models.ReferenceItem(name=f"CVSSv3.1 {item.cvss3}", url=f"https://nvd.nist.gov/vuln-metrics/cvss/v3-calculator?version=3.1&vector={item.cvss3}"))  # type: ignore
            if item.cve:
                for cve in item.cve:
                    item.references.append(models.ReferenceItem(name=cve, url=f"https://nvd.nist.gov/vuln/detail/{cve}"))  # type: ignore
            full_data.append(item)

    if not full_data:
        return Response(status_code=status.HTTP_204_NO_CONTENT)

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
    responses={
        204: {"description": "No scan data is present for this account"},
        401: {"description": "Authorization Header was sent but something was not valid (check the logs), likely signed the wrong HTTP method or forgot to sign the base64 encoded POST data"},
        403: {"description": "Authorization Header was not sent, or dropped at a proxy (requesters issue) or the CDN (that one is our server misconfiguration)"},
        500: {"description": "An unhandled error occured during an AWS request for data access"},
    },
    tags=["Scan Reports"],
)
@cachier(
    stale_after=timedelta(minutes=5),
    cache_dir=internals.CACHE_DIR,
    hash_params=lambda _, kw: services.helpers.parse_authorization_header(kw["authorization"])["id"]+str(kw.get("limit"))
)
def latest_findings(
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
        internals.logger.warning(f"No reports for {prefix_key}")
        return Response(status_code=status.HTTP_204_NO_CONTENT)

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
            if item.cvss2:
                item.references.append(models.ReferenceItem(name=f"CVSSv2 {item.cvss2}", url=f"https://nvd.nist.gov/vuln-metrics/cvss/v2-calculator?vector=({item.cvss2})"))  # type: ignore
            if item.cvss3:
                item.references.append(models.ReferenceItem(name=f"CVSSv3.1 {item.cvss3}", url=f"https://nvd.nist.gov/vuln-metrics/cvss/v3-calculator?version=3.1&vector={item.cvss3}"))  # type: ignore
            if item.cve:
                for cve in item.cve:
                    item.references.append(models.ReferenceItem(name=cve, url=f"https://nvd.nist.gov/vuln/detail/{cve}"))  # type: ignore
            full_data.append(item)

    if not full_data:
        return Response(status_code=status.HTTP_204_NO_CONTENT)

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
