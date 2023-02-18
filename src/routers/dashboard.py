import contextlib
import json
from datetime import timedelta

from fastapi import APIRouter, Response, status, Depends
from cachier import cachier

import internals
import models
import config
import services.sendgrid
import services.stripe
import services.aws
import services.helpers

router = APIRouter()


@router.get(
    "/dashboard/compliance",
    response_model=list[models.DashboardCompliance],
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
    tags=["Dashboard"],
)
@cachier(
    stale_after=timedelta(minutes=5),
    cache_dir=internals.CACHE_DIR,
    hash_params=lambda _, kw: kw["authz"].account.name,
)
def dashboard_compliance(
    response: Response,
    authz: internals.Authorization = Depends(internals.auth_required, use_cache=False),
):
    """
    Retrieves a collection of your clients
    """
    object_key = f"{internals.APP_ENV}/accounts/{authz.account.name}/computed/dashboard-compliance.json"
    try:
        raw = services.aws.get_s3(path_key=object_key)
        if not raw:
            return Response(status_code=status.HTTP_204_NO_CONTENT)
        data = json.loads(raw)
        for item in data:
            with contextlib.suppress(AttributeError):
                item["label"] = getattr(models.GraphLabel, item["label"])
        return data

    except RuntimeError as err:
        internals.logger.exception(err)
    response.status_code = status.HTTP_500_INTERNAL_SERVER_ERROR
    return


@router.get(
    "/dashboard/quotas",
    response_model=models.AccountQuotas,
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
    tags=["Dashboard"],
)
@cachier(
    stale_after=timedelta(seconds=30),
    cache_dir=internals.CACHE_DIR,
    hash_params=lambda _, kw: kw["authz"].account.name,
)
def dashboard_quotas(
    authz: internals.Authorization = Depends(internals.auth_required, use_cache=False),
):
    """
    Retrieves a collection of your clients
    """
    scanner_record = models.ScannerRecord(account_name=authz.account.name)  # type: ignore
    if scanner_record.load():
        return services.helpers.get_quotas(
            account=authz.account, scanner_record=scanner_record
        )
    return Response(status_code=status.HTTP_204_NO_CONTENT)


@router.get(
    "/findings/certificate",
    response_model=list[models.EvaluationItem],
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
    stale_after=timedelta(minutes=5),
    cache_dir=internals.CACHE_DIR,
    hash_params=lambda _, kw: kw["authz"].account.name + str(kw.get("limit")),
)
def certificate_issues(
    response: Response,
    limit: int = 20,
    authz: internals.Authorization = Depends(internals.auth_required, use_cache=False),
):
    """
    Retrieves a collection of your own Trivial Scanner reports, providing
    a list of certificate issues filtered to include only the highest risk
    and ordered by last seen
    """
    object_key = f"{internals.APP_ENV}/accounts/{authz.account.name}/computed/dashboard-certificates.json"
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
                item.description = config.get_rule_desc(
                    f"{item.group_id}.{item.rule_id}"
                )
            enriched_data.append(item)
        return list(reversed(sorted(enriched_data, key=lambda x: x.observed_at)))
    except RuntimeError as err:
        internals.logger.exception(err)
    response.status_code = status.HTTP_500_INTERNAL_SERVER_ERROR
    return


@router.get(
    "/findings/latest",
    response_model=list[models.EvaluationItem],
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
    stale_after=timedelta(minutes=5),
    cache_dir=internals.CACHE_DIR,
    hash_params=lambda _, kw: kw["authz"].account.name + str(kw.get("limit")),
)
def latest_findings(
    response: Response,
    limit: int = 20,
    authz: internals.Authorization = Depends(internals.auth_required, use_cache=False),
):
    """
    Retrieves a collection of your own Trivial Scanner reports, providing
    a list of host findings filtered to include only the highest risk issues
    and ordered by last seen
    """
    object_key = f"{internals.APP_ENV}/accounts/{authz.account.name}/computed/dashboard-findings.json"
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
                item.description = config.get_rule_desc(
                    f"{item.group_id}.{item.rule_id}"
                )

            for group in item.compliance or []:  # pylint: disable=not-an-iterable
                if (
                    config.pcidss4
                    and group.compliance == models.ComplianceName.PCI_DSS
                    and group.version == "4.0"
                ):
                    pci4_items = []
                    for compliance in group.items or []:
                        compliance.description = (
                            config.pcidss4.requirements.get(compliance.requirement, "")
                            if compliance.requirement
                            else None
                        )
                        pci4_items.append(compliance)
                    group.items = pci4_items
                if (
                    config.pcidss3
                    and group.compliance == models.ComplianceName.PCI_DSS
                    and group.version == "3.2.1"
                ):
                    pci3_items = []
                    for compliance in group.items or []:
                        compliance.description = (
                            config.pcidss3.requirements.get(compliance.requirement, "")
                            if compliance.requirement
                            else None
                        )
                        pci3_items.append(compliance)
                    group.items = pci3_items
                if group.compliance in [
                    models.ComplianceName.NIST_SP800_131A,
                    models.ComplianceName.FIPS_140_2,
                ]:
                    group.items = None

            if config.mitre_attack:
                for threat in item.threats or []:  # pylint: disable=not-an-iterable
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
                                threat.sub_technique_description = (
                                    sub_technique.description
                                )

            enriched_data.append(item)
        return list(reversed(sorted(enriched_data, key=lambda x: x.observed_at)))
    except RuntimeError as err:
        internals.logger.exception(err)
    response.status_code = status.HTTP_500_INTERNAL_SERVER_ERROR
