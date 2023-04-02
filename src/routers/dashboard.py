import contextlib
import json
from datetime import date, timedelta, datetime, timezone

from fastapi import APIRouter, Response, status, Depends
from cachier import cachier
from boto3.dynamodb.conditions import Key

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
    if scanner_record.load(load_history=True):
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
    response_model=list[models.Finding],
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
    tags=["Scan Reports", "Findings"],
)
@cachier(
    stale_after=timedelta(seconds=5),
    cache_dir=internals.CACHE_DIR,
    hash_params=lambda _, kw: kw["authz"].account.name + str(kw.get("limit")),
)
def latest_findings(
    response: Response,
    limit: int = 50,
    authz: internals.Authorization = Depends(internals.auth_required, use_cache=False),
):
    """
    Retrieves a collection of your own Trivial Scanner reports, providing
    a list of host findings filtered to include only the highest risk issues
    and ordered by last seen
    """
    try:
        latest = []
        for item in services.aws.query_dynamodb(
            table_name=services.aws.Tables.FINDINGS,
            IndexName="account_name-index",
            KeyConditionExpression=Key("account_name").eq(authz.account.name),
        ):
            finding = models.Finding(
                **services.aws.get_dynamodb(  # type: ignore
                    table_name=services.aws.Tables.FINDINGS,
                    item_key={"finding_id": item["finding_id"]},
                )
            )
            if not finding.occurrences:
                finding.delete()
                continue
            future_deferred = filter(
                lambda occurrence: occurrence.status == models.FindingStatus.DEFERRED
                and occurrence.deferred_to
                and occurrence.deferred_to > date.today(),
                finding.occurrences,
            )
            finding.occurrences = [
                x for x in finding.occurrences.copy() if x not in future_deferred
            ]
            closed = filter(
                lambda occurrence: occurrence.status == models.FindingStatus.WONT_FIX,
                finding.occurrences,
            )
            finding.occurrences = [
                x for x in finding.occurrences.copy() if x not in closed
            ]
            remediated = filter(
                lambda occurrence: occurrence.status == models.FindingStatus.REMEDIATED,
                finding.occurrences,
            )
            finding.occurrences = [
                x for x in finding.occurrences.copy() if x not in remediated
            ]
            if not finding.occurrences:
                continue
            finding.description = config.get_rule_desc(
                f"{finding.group_id}.{finding.rule_id}"
            )
            latest.append(finding)

        return list(reversed(sorted(latest[:limit], key=lambda x: x.observed_at)))
    except RuntimeError as err:
        internals.logger.exception(err)
    response.status_code = status.HTTP_500_INTERNAL_SERVER_ERROR


@router.post(
    "/finding/status",
    response_model=bool,
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
    tags=["Findings"],
)
async def update_finding_status(
    request: models.FindingStatusRequest,
    authz: internals.Authorization = Depends(internals.auth_required, use_cache=False),
):
    """
    updates a finding occurrence status
    """
    internals.logger.info(request.dict())
    finding = models.Finding(finding_id=request.finding_id)  # type: ignore
    if not finding.load():
        return Response(status_code=status.HTTP_404_NOT_FOUND)
    if finding.account_name != authz.account.name:
        return Response(status_code=status.HTTP_406_NOT_ACCEPTABLE)
    if not finding.occurrences:
        finding.delete()
        return Response(status_code=status.HTTP_302_FOUND)

    occurrences = []
    update = False
    for occurrence in finding.occurrences:
        if occurrence.status == request.status:
            occurrences.append(occurrence)
            continue
        if str(occurrence.occurrence_id) == request.occurrence_id:
            occurrence.status = request.status
            update = True
            if (
                occurrence.status == models.FindingStatus.DEFERRED
                and not occurrence.deferred_to
            ):
                occurrence.deferred_to = datetime.now(tz=timezone.utc) + timedelta(
                    days=7
                )
            if occurrence.status == models.FindingStatus.REMEDIATED:
                occurrence.remediated_at = datetime.now(tz=timezone.utc)
            if occurrence.status == models.FindingStatus.TRIAGED:
                occurrence.triaged_at = datetime.now(tz=timezone.utc)
            if occurrence.status == models.FindingStatus.WONT_FIX:
                occurrence.closed_at = datetime.now(tz=timezone.utc)
            occurrences.append(occurrence)
            break
        occurrences.append(occurrence)

    if update:
        finding.occurrences = occurrences
        return finding.save()

    return Response(status_code=status.HTTP_204_NO_CONTENT)


@router.post(
    "/finding/deferred",
    response_model=bool,
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
    tags=["Findings"],
)
async def update_finding_deferred_to(
    request: models.FindingDeferredToRequest,
    authz: internals.Authorization = Depends(internals.auth_required, use_cache=False),
):
    """
    updates a finding occurrence deferred_to
    """
    internals.logger.info(request.dict())
    finding = models.Finding(finding_id=request.finding_id)  # type: ignore
    if not finding.load():
        return Response(status_code=status.HTTP_404_NOT_FOUND)
    if finding.account_name != authz.account.name:
        return Response(status_code=status.HTTP_406_NOT_ACCEPTABLE)
    if not finding.occurrences:
        finding.delete()
        return Response(status_code=status.HTTP_302_FOUND)

    occurrences = []
    update = False
    for occurrence in finding.occurrences:
        if occurrence.deferred_to == request.deferred_to:
            occurrences.append(occurrence)
            continue
        if str(occurrence.occurrence_id) == request.occurrence_id:
            occurrence.deferred_to = request.deferred_to
            update = True
            occurrences.append(occurrence)
            break
        occurrences.append(occurrence)

    if update:
        finding.occurrences = occurrences
        return finding.save()

    return Response(status_code=status.HTTP_204_NO_CONTENT)
