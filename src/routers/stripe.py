from fastapi import Header, APIRouter, Response, status
from starlette.requests import Request
import stripe
from stripe.error import SignatureVerificationError

import internals
import services.aws
import services.stripe

router = APIRouter()

@router.post("/stripe/webhook",
    status_code=status.HTTP_200_OK,
    include_in_schema=False,
)
async def webhook_received(
    request: Request,
    response: Response,
    stripe_signature=Header(),
):
    """
    Handle Stripe webhook events
    """
    try:
        webhook_secret = services.aws.get_ssm(f"/{internals.APP_ENV}/{internals.APP_NAME}/Stripe/webhook-key", WithDecryption=True)
        raw_body = await request.body()
        event = stripe.Webhook.construct_event(
            payload=raw_body,
            sig_header=stripe_signature,
            secret=webhook_secret,
        )
        webhook = services.stripe.Webhook(
            api_version=event['api_version'],
            event_id=event['data'],
            created=event['created'],
            data_object=event['data']['object'],
            event_type=event['type'],
        )
        internals.logger.info(f'Stripe Webhook [{webhook.event_type}]')
        return {'success': webhook.process()}
    except ValueError as err:
        response.status_code = status.HTTP_400_BAD_REQUEST
        internals.logger.critical(err)
    except SignatureVerificationError as err:
        response.status_code = status.HTTP_403_FORBIDDEN
        internals.logger.critical(err)

    return {'success': False}
