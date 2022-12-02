from fastapi import Header, APIRouter, Response, status
from starlette.requests import Request

import internals
import services.aws
import services.sendgrid

router = APIRouter()


@router.post("/webhook",
             status_code=status.HTTP_200_OK,
             include_in_schema=False,
             )
async def webhook_received(
    request: Request,
    response: Response,
    twilio_email_event_webhook_signature=Header(default=None),
    twilio_email_event_webhook_timestamp=Header(default=None),
):
    """
    Handle Sendgrid webhook events
    """
    raw_body = await request.body()
    internals.logger.info(raw_body.decode())
    internals.logger.info(f"signature {twilio_email_event_webhook_signature} timestamp {twilio_email_event_webhook_timestamp}")
    try:
        if any([not twilio_email_event_webhook_signature, not twilio_email_event_webhook_timestamp]) or services.sendgrid.verify_signature(raw_body.decode(), twilio_email_event_webhook_signature, twilio_email_event_webhook_timestamp):
            return {'success': services.sendgrid.process_webhook(raw_body.decode())}
    except services.sendgrid.SendgridValidationError as err:
        response.status_code = status.HTTP_401_UNAUTHORIZED
        internals.logger.debug(raw_body)
        internals.logger.critical(err)

    return {'success': False}
