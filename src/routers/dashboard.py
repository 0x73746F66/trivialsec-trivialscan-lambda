from typing import Union

from fastapi import Header, APIRouter, Response, status
from starlette.requests import Request

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
            tags=["Dashboard"],
            )
async def dashboard_compliance(
    request: Request,
    response: Response,
    authorization: Union[str, None] = Header(default=None),
):
    """
    Retrieves a collection of your clients
    """
    if not authorization:
        response.headers['WWW-Authenticate'] = 'HMAC realm="Authorization Required"'
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
        response.headers['WWW-Authenticate'] = 'HMAC realm="Login Required"'
        return

    summary_keys = []
    charts = []
    results = []
    prefix_key = f"{internals.APP_ENV}/accounts/{authz.account.name}/results/"  # type: ignore
    try:
        summary_keys = services.aws.list_s3(prefix_key)

    except RuntimeError as err:
        response.status_code = status.HTTP_500_INTERNAL_SERVER_ERROR
        internals.logger.exception(err)
        return []

    chart_data = {
        models.GraphLabel.PCIDSS3: {'week': [], 'month': [], 'year': []},
        models.GraphLabel.PCIDSS4: {'week': [], 'month': [], 'year': []},
        models.GraphLabel.NISTSP800_131A_STRICT: {'week': [], 'month': [], 'year': []},
        models.GraphLabel.NISTSP800_131A_TRANSITION: {'week': [], 'month': [], 'year': []},
        models.GraphLabel.FIPS1402: {'week': [], 'month': [], 'year': []},
    }
    _data = {'week': 0, 'month': 0, 'year': 0}
    for summary_key in summary_keys:
        if not summary_key.endswith("full-report.json"):
            continue
        report = models.FullReport(
            account_name=authz.account.name,  # type: ignore
            report_id=summary_key.replace(
                prefix_key, '').replace("/full-report.json", '')
        ).load()
        group_name, range_group = services.helpers.date_label(report.date)  # type: ignore
        cur_results = {"group_name": group_name}
        for item in report.evaluations:  # type: ignore
            if item.result_level == "pass":
                continue
            for compliance in item.compliance:  # type: ignore
                if compliance.compliance == "PCI DSS":
                    if compliance.version == "3.2.1":
                        cur_results.setdefault(models.GraphLabel.PCIDSS3, _data.copy())  # type: ignore
                        cur_results[models.GraphLabel.PCIDSS3][range_group] += 1  # type: ignore
                    if compliance.version == "4.0":
                        cur_results.setdefault(models.GraphLabel.PCIDSS4, _data.copy())  # type: ignore
                        cur_results[models.GraphLabel.PCIDSS4][range_group] += 1  # type: ignore
                if compliance.compliance == "NIST SP800-131A":
                    if compliance.version == "strict mode":
                        cur_results.setdefault(models.GraphLabel.NISTSP800_131A_STRICT, _data.copy())  # type: ignore
                        cur_results[models.GraphLabel.NISTSP800_131A_STRICT][range_group] += 1  # type: ignore
                    if compliance.version == "transition mode":
                        cur_results.setdefault(models.GraphLabel.NISTSP800_131A_TRANSITION, _data.copy())  # type: ignore
                        cur_results[models.GraphLabel.NISTSP800_131A_TRANSITION][range_group] += 1  # type: ignore
                if compliance.compliance == "FIPS 140-2" and compliance.version == "Annex A":
                    cur_results.setdefault(models.GraphLabel.FIPS1402, _data.copy())  # type: ignore
                    cur_results[models.GraphLabel.FIPS1402][range_group] += 1  # type: ignore
        results.append(cur_results)

    agg_sums = {}
    for c, _ in chart_data.items():
        agg_sums.setdefault(c, {})
        for r in ['week', 'month', 'year']:
            agg_sums[c].setdefault(r, {})
            for _result in results:
                if c not in _result or r not in _result[c]:
                    continue
                agg_sums[c][r].setdefault(_result['group_name'], [])
                agg_sums[c][r][_result['group_name']].append(_result[c][r])
    for c, g in agg_sums.items():
        for r, d in g.items():
            for group_name, sum_arr in d.items():
                if sum(sum_arr) > 0:
                    chart_data[c][r].append(
                        models.ComplianceChartItem(
                            name=group_name,
                            num=sum(sum_arr)
                        )
                    )
    for c, d in chart_data.items():
        ranges = set()
        for r in ['week', 'month', 'year']:
            if d[r]:
                ranges.add(r)

        charts.append(
            models.DashboardCompliance(
                label=c,
                ranges=list(ranges),
                data=d  # type: ignore
            )
        )

    return charts

@router.get("/dashboard/quotas",
            response_model=models.DashboardQuotas,
            response_model_exclude_unset=True,
            response_model_exclude_none=True,
            status_code=status.HTTP_200_OK,
            tags=["Dashboard"],
            )
async def dashboard_quotas(
    request: Request,
    response: Response,
    authorization: Union[str, None] = Header(default=None),
):
    """
    Retrieves a collection of your clients
    """
    if not authorization:
        response.headers['WWW-Authenticate'] = 'HMAC realm="Authorization Required"'
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
        response.headers['WWW-Authenticate'] = 'HMAC realm="Login Required"'
        return

    new_only = True
    unlimited_monitoring = False
    unlimited_scans = False
    monitoring_total = 1
    monitoring = 0
    passive_total = 0
    passive = 0
    active_total = 0
    active = 0
    if sub := models.SubscriptionAddon().load(authz.account.name):  # type: ignore
        unlimited_scans = True
        new_only = False
    if sub := models.SubscriptionBooster().load(authz.account.name):  # type: ignore
        monitoring_total = 1 if sub.quantity is None else sub.quantity + 1
    elif sub := models.SubscriptionPro().load(authz.account.name):  # type: ignore
        monitoring_total = 10 if not sub.metadata else sub.metadata.get("monitoring", 10)
        passive_total = 500 if not sub.metadata else sub.metadata.get("managed_passive", 500)
        active_total = 50 if not sub.metadata else sub.metadata.get("managed_active", 50)
        new_only = False
    elif sub := models.SubscriptionEnterprise().load(authz.account.name):  # type: ignore
        monitoring_total = 50 if not sub.metadata else sub.metadata.get("monitoring", 50)
        passive_total = 1000 if not sub.metadata else sub.metadata.get("managed_passive", 1000)
        active_total = 100 if not sub.metadata else sub.metadata.get("managed_active", 100)
        new_only = False
    elif sub := models.SubscriptionUnlimited().load(authz.account.name):  # type: ignore
        monitoring_total = None
        passive_total = None
        active_total = None
        new_only = False

    return models.DashboardQuotas(
        unlimited_monitoring=unlimited_monitoring,
        unlimited_scans=unlimited_scans,
        monitoring={
            models.Quota.PERIOD: "Daily",
            models.Quota.TOTAL: monitoring_total,
            models.Quota.USED: monitoring,
        },
        passive={
            models.Quota.PERIOD: "Only new hosts" if new_only else "Daily",
            models.Quota.TOTAL: passive_total,
            models.Quota.USED: passive,
        },
        active={
            models.Quota.PERIOD: "Daily",
            models.Quota.TOTAL: active_total,
            models.Quota.USED: active,
        },
    )
