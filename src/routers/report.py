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
# @cachier(
#     stale_after=timedelta(minutes=5),
#     cache_dir=internals.CACHE_DIR,
#     hash_params=lambda _, kw: services.helpers.parse_authorization_header(kw["authorization"])["id"]+str(kw.get("report_id"))+str(kw.get("full_certs"))+str(kw.get("full_hosts"))
# )
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

    evaluations = []
    for item in report.evaluations or []:
        if not item.observed_at:
            item.observed_at = report.date
        if item.cvss2:
            item.references.append(models.ReferenceItem(name=f"CVSSv2 {item.cvss2}", url=f"https://nvd.nist.gov/vuln-metrics/cvss/v2-calculator?vector=({item.cvss2})"))  # type: ignore
        if item.cvss3:
            item.references.append(models.ReferenceItem(name=f"CVSSv3.1 {item.cvss3}", url=f"https://nvd.nist.gov/vuln-metrics/cvss/v3-calculator?version=3.1&vector={item.cvss3}"))  # type: ignore
        if item.cve:
            for cve in item.cve:
                item.references.append(models.ReferenceItem(name=cve, url=f"https://nvd.nist.gov/vuln/detail/{cve}"))  # type: ignore
        if not item.description:
            item.description = config.get_rule_desc(f"{item.group_id}.{item.rule_id}")

        groups = []
        for group in item.compliance or []:
            if config.pcidss4 and group.compliance == models.ComplianceName.PCI_DSS and group.version == '4.0':
                pci4_items = []
                for compliance in group.items or []:
                    compliance.description = None if not compliance.requirement else config.pcidss4.requirements.get(compliance.requirement)
                    pci4_items.append(compliance)
                group.items = pci4_items
            if config.pcidss3 and group.compliance == models.ComplianceName.PCI_DSS and group.version == '3.2.1':
                pci3_items = []
                for compliance in group.items or []:
                    compliance.description = None if not compliance.requirement else config.pcidss3.requirements.get(compliance.requirement)
                    pci3_items.append(compliance)
                group.items = pci3_items
            groups.append(groups)
        if config.mitre_attack:
            threats = []
            for threat in item.threats or []:
                for tactic in config.mitre_attack.tactics:
                    if tactic.id == threat.tactic_id:
                        threat.tactic_description = tactic.description
                for data_source in config.mitre_attack.data_sources:
                    if data_source.id == threat.data_source_id:
                        threat.data_source_description = data_source.description
                for mitigation in config.mitre_attack.mitigations:
                    if mitigation.id == threat.mitigation_id:
                        threat.mitigation_description = mitigation.description
                for technique in config.mitre_attack.techniques:
                    if technique.id == threat.technique_id:
                        threat.technique_description = technique.description
                    for sub_technique in technique.sub_techniques or []:
                        if sub_technique.id == threat.sub_technique_id:
                            threat.sub_technique_description = sub_technique.description
                threats.append(threat)
            item.threats = threats

        evaluations.append(item)
    report.evaluations = evaluations

    hosts = []
    for host in report.targets:
        host.scanning_status = services.helpers.host_scanning_status(authz.account, host.transport.hostname)  # type: ignore
        hosts.append(host)
    report.targets = hosts

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

    summaries = []
    data = []
    raw = None
    object_key = f"{internals.APP_ENV}/accounts/{authz.account.name}/computed/summaries.json"  # type: ignore
    try:
        raw = services.aws.get_s3(path_key=object_key)

    except RuntimeError as err:
        response.status_code = status.HTTP_500_INTERNAL_SERVER_ERROR
        internals.logger.exception(err)
        return []

    if not raw:
        return Response(status_code=status.HTTP_204_NO_CONTENT)

    cache_data = {}
    summaries = json.loads(raw)
    for item in summaries:
        report = models.ReportSummary(**item)
        if report.client_name in cache_data:
            report.client = cache_data[report.client_name]
            data.append(report)
            continue
        if report.client_name:
            if client := models.Client(account=authz.account, name=report.client_name).load():  # type: ignore
                report.client = client.client_info
                cache_data[report.client_name] = client.client_info
        data.append(report)

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
        ret = services.aws.get_s3(path_key=cert_key)
        if not ret:
            return Response(status_code=status.HTTP_204_NO_CONTENT)
        if include_pem:
            ret["pem"] = services.aws.get_s3(path_key=pem_key)

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
        results_uri = f"/result/{report_id}/detail"
        report = models.ReportSummary(report_id=report_id, results_uri=results_uri, **data)
        if report.save():
            scans_map: dict[str, dict[str, list[str]]] = {}
            object_key = f"{internals.APP_ENV}/accounts/{authz.account.name}/scan-history.json"  # type: ignore
            if history_raw := services.aws.get_s3(path_key=object_key):
                scans_map: dict[str, dict[str, list[str]]] = json.loads(history_raw)
            for target in report.targets or []:
                scans_map.setdefault(target, {'reports': []})  # type: ignore
                scans_map[target]['reports'].append(report.report_id)  # type: ignore
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
                rule_id=_item['rule_id'],
                group=_item['group'],
                group_id=_item['group_id'],
                key=_item['key'],
                name=_item['name'],
                result_value=_item['result_value'],
                result_label=_item['result_label'],
                result_text=_item['result_text'],
                result_level=_item['result_level'],
                score=_item['score'],
                description=_item.get('description', config.get_rule_desc(f"{_item['rule_id']}.{_item['group_id']}")),
                metadata=_item.get('metadata', {}),
                cve=_item.get('cve', []),
                cvss2=_item.get('cvss2'),
                cvss3=_item.get('cvss3'),
                references=[models.ReferenceItem(name=ref['name'], url=ref['url']) for ref in _item.get('references', []) or []],
                compliance=[models.ComplianceGroup(compliance=comp['compliance'], version=comp['version'], items=[
                    models.ComplianceItem(**item) for item in comp.get('items', [])
                ]) for comp in _item['compliance']],
                threats=[models.ThreatItem(**threat) for threat in _item.get('threats', [])],
                transport=models.HostTransport(**data['transport']),
                certificate=None if not _item.get('certificate') else models.Certificate(**_item['certificate']),
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

    object_key = f"{internals.APP_ENV}/accounts/{authz.account.name}/computed/dashboard-certificates.json"  # type: ignore
    try:
        raw = services.aws.get_s3(path_key=object_key)
        if not raw:
            return Response(status_code=status.HTTP_204_NO_CONTENT)
        data = json.loads(raw)
        latest_data: list[models.EvaluationItem] = data[:limit]
        enriched_data = []
        for item in latest_data:
            if not item.description:
                item.description = config.get_rule_desc(f"{item.group_id}.{item.rule_id}")
            enriched_data.append(item)
        sorted_data = list(reversed(sorted(enriched_data, key=lambda x: x['observed_at'])))  # type: ignore

        return sorted_data

    except RuntimeError as err:
        internals.logger.exception(err)
    response.status_code = status.HTTP_500_INTERNAL_SERVER_ERROR
    return


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

    object_key = f"{internals.APP_ENV}/accounts/{authz.account.name}/computed/dashboard-findings.json"  # type: ignore
    try:
        raw = services.aws.get_s3(path_key=object_key)
        if not raw:
            return Response(status_code=status.HTTP_204_NO_CONTENT)
        data = json.loads(raw)
        latest_data: list[models.EvaluationItem] = data[:limit]
        enriched_data = []
        for item in latest_data:
            if not item.description:
                item.description = config.get_rule_desc(f"{item.group_id}.{item.rule_id}")
            enriched_data.append(item)
        sorted_data = list(reversed(sorted(enriched_data, key=lambda x: x['observed_at'])))  # type: ignore

        return sorted_data

    except RuntimeError as err:
        internals.logger.exception(err)
    response.status_code = status.HTTP_500_INTERNAL_SERVER_ERROR
    return
