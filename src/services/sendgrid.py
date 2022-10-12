import logging
from typing import Union
import requests
from sendgrid import SendGridAPIClient

import services.aws
import internals

logger = logging.getLogger()

SENDGRID_TEMPLATES = {
    "account_recovery": "d-da9d3ba3389643289b8d3596e902068d",
    "magic_link": "d-48aa0ed2e9ff442ea6ee9b73ac984b96",
    "recovery_request": "d-1958843496444e7bb8e29f4277e74182",
    "registrations": "d-a0a115275e404b32bf96b540ecdffeda",
    "subscriptions": "d-1d20f029d4eb46b5957c253c3ccd3262",
    "updated_email": "d-fef742bc0a754165a8778f4929df3dbb",
    "invitations": "d-c4a471191062414ea3cefd67c98deed4",
    "support": "d-821ef38856bb4d0581f26c4745ce00e7",
}
SENDGRID_GROUPS = {
    'notifications': 18318,
    'focus_group': 18317,
    'subscriptions': 18319,
    'marketing': 18316,
}
SENDGRID_LISTS = {
    'subscribers': "09998a12-998c-4ca8-990d-2c5e66f0c0ef",
    'members': "ce2b465e-60cd-426c-9ac1-78cdb8e9a4c4",
    'trials': "f0c56ac3-7317-4b39-9a26-b4e37bc33efd",
}


def send_email(
    subject: str,
    template: str,
    data: dict,
    recipient: str,
    group: str = 'notifications',
    sender: str = 'support@trivialsec.com',
    sender_name: str = 'Chris @ Trivial Security',
    bcc: Union[str, None] = "support@trivialsec.com"
):
    sendgrid_api_key = services.aws.get_ssm(
        f'/{internals.APP_ENV}/Deploy/{internals.APP_NAME}/sendgrid_api_key', WithDecryption=True)
    sendgrid = SendGridAPIClient(sendgrid_api_key)
    tmp_url = sendgrid.client.mail.send._build_url(query_params={})  # pylint: disable=protected-access
    personalization = {
        'subject': subject,
        'dynamic_template_data': {**data, **{'email': recipient}},
        'to': [
            {
                'email': recipient
            }
        ],
    }
    if bcc is not None and bcc != recipient:
        personalization['bcc'] = [
            {
                'email': bcc,
                'enable': bcc is not None and bcc != recipient
            }
        ]
    req_body = {
        'subject': subject,
        'from': {'email': "donotreply@trivialsec.com", 'name': sender_name},
        'reply_to': {'email': sender},
        'mail_settings': {
            'bcc': {'email': bcc, 'enable': bcc is not None and bcc != recipient},
            "footer": {
                "enable": False,
            },
            "sandbox_mode": {
                "enable": internals.APP_ENV != "Prod"
            }
        },
        'template_id': SENDGRID_TEMPLATES.get(template),
        'asm': {
            'group_id': SENDGRID_GROUPS.get(group)
        },
        'personalizations': [personalization],
    }
    res = requests.post(
        url=tmp_url,
        json=req_body,
        headers=sendgrid.client.request_headers,
        timeout=10
    )
    logger.info(res.__dict__)
    return res


def upsert_contact(recipient_email: str, list_name: str = 'subscribers'):
    sendgrid_api_key = services.aws.get_ssm(
        f'/{internals.APP_ENV}/Deploy/{internals.APP_NAME}/sendgrid_api_key', WithDecryption=True)
    sendgrid = SendGridAPIClient(sendgrid_api_key)
    res = requests.put(
        url='https://api.sendgrid.com/v3/marketing/contacts',
        json={
            "list_ids": [
                SENDGRID_LISTS.get(list_name)
            ],
            "contacts": [{
                "email": recipient_email
            }]
        },
        headers=sendgrid.client.request_headers,
        timeout=10
    )
    logger.debug(res.__dict__)
    return res
