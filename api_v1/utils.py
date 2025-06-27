# utils.py
import threading
from twilio.rest import Client
from django.conf import settings
_user = threading.local()

def set_current_user(user):
    _user.value = user

def get_current_user():
    return getattr(_user, 'value', None)



def send_whatsapp_message(to, message):
    client = Client(settings.TWILIO_ACCOUNT_SID, settings.TWILIO_AUTH_TOKEN)
    return client.messages.create(
        from_=f'whatsapp:{settings.TWILIO_WHATSAPP_NUMBER}',
        to=f'whatsapp:{to}',
        body=message,
    )

def send_sms(to, message):
    client = Client(settings.TWILIO_ACCOUNT_SID, settings.TWILIO_AUTH_TOKEN)
    return client.messages.create(
        from_=settings.TWILIO_SMS_NUMBER,
        to=to,
        body=message,
    )

class TwilioMessaging:
    def __init__(self):
        self.client = Client(settings.TWILIO_ACCOUNT_SID, settings.TWILIO_AUTH_TOKEN)

    def send_whatsapp_message(self, to, message):
        return self.client.messages.create(
            from_=f'whatsapp:{settings.TWILIO_WHATSAPP_NUMBER}',
            to=f'whatsapp:{to}',
            body=message,
        )

    def send_sms(self, to, message):
        return self.client.messages.create(
            from_=settings.TWILIO_SMS_NUMBER,
            to=to,
            body=message,
        )
def send_whatsapp_message(to, message):
    """
    Send a WhatsApp message using Twilio API.
    Args:
        to (str): Recipient's WhatsApp number (e.g., 'whatsapp:+1234567890').
        message (str): Message body to send.
    Returns:
        str: Message SID if sent successfully.
    """
    client = Client(settings.TWILIO_ACCOUNT_SID, settings.TWILIO_AUTH_TOKEN)
    response = client.messages.create(
        from_=settings.TWILIO_WHATSAPP_NUMBER,
        to=to,
        body=message,
    )
    return response.sid

def send_sms(to, message):
    client = Client(settings.TWILIO_ACCOUNT_SID, settings.TWILIO_AUTH_TOKEN)
    try:
        response = client.messages.create(
            from_=settings.TWILIO_SMS_NUMBER,  # Twilio phone number
            to=to,  # Recipient's phone number
            body=message,  # SMS body
        )
        return {"message": "SMS sent successfully", "sid": response.sid}
    except Exception as e:
        return {"error": str(e)}