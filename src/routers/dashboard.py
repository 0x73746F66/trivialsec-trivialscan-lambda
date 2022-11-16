import json
from typing import Union
from datetime import timedelta

from fastapi import Header, APIRouter, Response, status
from starlette.requests import Request
from cachier import cachier
from markdown import markdown

import internals
import models
import config
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
        latest_data: list[dict] = data[:limit]
        enriched_data = []
        for _item in latest_data:
            item = models.EvaluationItem(**_item)
            if not item.description:
                item.description = markdown(config.get_rule_desc(f"{item.group_id}.{item.rule_id}"))
            enriched_data.append(item)
        sorted_data = list(reversed(sorted(enriched_data, key=lambda x: x.observed_at)))  # type: ignore

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
        latest_data: list[dict] = data[:limit]
        enriched_data = []
        for _item in latest_data:
            item = models.EvaluationItem(**_item)
            if not item.description:
                item.description = markdown(config.get_rule_desc(f"{item.group_id}.{item.rule_id}"))

            for group in item.compliance or []:
                if config.pcidss4 and group.compliance == models.ComplianceName.PCI_DSS and group.version == '4.0':
                    pci4_items = []
                    for compliance in group.items or []:
                        compliance.description = None if not compliance.requirement else markdown(config.pcidss4.requirements.get(compliance.requirement, ''))
                        pci4_items.append(compliance)
                    group.items = pci4_items
                if config.pcidss3 and group.compliance == models.ComplianceName.PCI_DSS and group.version == '3.2.1':
                    pci3_items = []
                    for compliance in group.items or []:
                        compliance.description = None if not compliance.requirement else markdown(config.pcidss3.requirements.get(compliance.requirement, ''))
                        pci3_items.append(compliance)
                    group.items = pci3_items
                if group.compliance in [models.ComplianceName.NIST_SP800_131A, models.ComplianceName.FIPS_140_2]:
                    group.items = None

            if config.mitre_attack:
                for threat in item.threats or []:
                    for tactic in config.mitre_attack.tactics:
                        if tactic.id == threat.tactic_id:
                            threat.tactic_description = markdown(tactic.description)
                    for data_source in config.mitre_attack.data_sources:
                        if data_source.id == threat.data_source_id:
                            threat.data_source_description = markdown(data_source.description)
                    for mitigation in config.mitre_attack.mitigations:
                        if mitigation.id == threat.mitigation_id:
                            threat.mitigation_description = markdown(mitigation.description)
                    for technique in config.mitre_attack.techniques:
                        if technique.id == threat.technique_id:
                            threat.technique_description = markdown(technique.description)
                        for sub_technique in technique.sub_techniques or []:
                            if sub_technique.id == threat.sub_technique_id:
                                threat.sub_technique_description = markdown(sub_technique.description)

            enriched_data.append(item)
        sorted_data = list(reversed(sorted(enriched_data, key=lambda x: x.observed_at)))  # type: ignore

        return sorted_data

    except RuntimeError as err:
        internals.logger.exception(err)
    response.status_code = status.HTTP_500_INTERNAL_SERVER_ERROR
    return
