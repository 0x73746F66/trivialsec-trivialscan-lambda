from fastapi import Header, APIRouter, Response, status
from starlette.requests import Request

import internals
import models
import services.stripe

router = APIRouter()


@router.post("/stripe/webhook",
    status_code=status.HTTP_200_OK,
    tags=["Stripe"],
)
async def webhook_received(
    request: Request,
    response: Response,
    stripe_signature=Header(None),
    data: models.StripeEvent,
):
    """
    Handle Stripe webhook events
    """
    event = request.scope.get("aws.event", {})
    raw_body = await request.body()
    try:
        event = stripe.Webhook.construct_event(
            payload=raw_body,
            sig_header=stripe_signature,
            secret=webhook_secret,
        )
    except ValueError as e:
        # Invalid payload
        raise e
    except stripe.error.SignatureVerificationError as e:
        # Invalid signature
        raise e

    return {'success': True}


@router.post("/stripe/checkout-session",
             status_code=status.HTTP_200_OK,
             tags=["Stripe"],
             )
def create_checkout_session(
    posterID: str,
):
    domain_url = os.getenv("DOMAIN") or "http://localhost:3000"
    album_price = os.getenv("POSTER_PRICE")

    try:
        checkout_session = stripe.checkout.Session.create(
            success_url=domain_url
            + "/order-confirmation?session_id={CHECKOUT_SESSION_ID}",
            cancel_url=domain_url + "/create-poster",
            client_reference_id=userID,
            payment_method_types=["card"],
            mode="payment",
            metadata={"poster_id": posterID},
            line_items=[{"price": album_price, "quantity": 1}],
        )
        return {"sessionId": checkout_session["id"]}
    except Exception as e:
        raise HTTPException(status_code=403, detail=str(e))
