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
        401: {"description": "Authorization Header was sent but something was not valid (check the logs), likely signed the wrong HTTP method or forgot to sign the base64 encoded POST data"},
        403: {"description": "Authorization Header was not sent, or dropped at a proxy (requesters issue) or the CDN (that one is our server misconfiguration)"},
        500: {"description": "An unhandled error occured during an AWS request for data access"},
    },
    tags=["Dashboard"],
)
@cachier(
    stale_after=timedelta(minutes=15),
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

    summary_keys = []
    charts = []
    results = []
    prefix_key = f"{internals.APP_ENV}/accounts/{authz.account.name}/results/"  # type: ignore
    try:
        summary_keys = services.aws.list_s3(prefix_key=prefix_key)

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
            report_id=summary_key.replace(prefix_key, '').replace("/full-report.json", '')).load()
        group_name, range_group, timestamp = services.helpers.date_label(report.date)  # type: ignore
        cur_results = {"group_name": group_name, "timestamp": timestamp}
        for item in report.evaluations:  # type: ignore
            if item.result_level == "pass":
                continue
            for compliance in item.compliance:  # type: ignore
                if compliance.compliance == models.ComplianceName.PCI_DSS:
                    if compliance.version == "3.2.1":
                        cur_results.setdefault(models.GraphLabel.PCIDSS3, _data.copy())  # type: ignore
                        cur_results[models.GraphLabel.PCIDSS3][range_group] += 1  # type: ignore
                    if compliance.version == "4.0":
                        cur_results.setdefault(models.GraphLabel.PCIDSS4, _data.copy())  # type: ignore
                        cur_results[models.GraphLabel.PCIDSS4][range_group] += 1  # type: ignore
                if compliance.compliance == models.ComplianceName.NIST_SP800_131A:
                    if compliance.version == "strict mode":
                        cur_results.setdefault(models.GraphLabel.NISTSP800_131A_STRICT, _data.copy())  # type: ignore
                        cur_results[models.GraphLabel.NISTSP800_131A_STRICT][range_group] += 1  # type: ignore
                    if compliance.version == "transition mode":
                        cur_results.setdefault(models.GraphLabel.NISTSP800_131A_TRANSITION, _data.copy())  # type: ignore
                        cur_results[models.GraphLabel.NISTSP800_131A_TRANSITION][range_group] += 1  # type: ignore
                if compliance.compliance == models.ComplianceName.FIPS_140_2 and compliance.version == "Annex A":
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
                key = (_result['group_name'], _result['timestamp'])
                agg_sums[c][r].setdefault(key, [])
                agg_sums[c][r][key].append(_result[c][r])
    for c, g in agg_sums.items():
        for r, d in g.items():
            for group_key, sum_arr in d.items():
                group_name, timestamp = group_key
                if sum(sum_arr) > 0:
                    chart_data[c][r].append(
                        models.ComplianceChartItem(
                            name=group_name,
                            num=sum(sum_arr),
                            timestamp=timestamp,
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
