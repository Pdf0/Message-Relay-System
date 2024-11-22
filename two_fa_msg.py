import pyotp
from twilio.rest import Client

account_sid = "ACf3bacac5ef57f4063fe437ba43f10fb5"
auth_token = "6a68aac26d3b25db69655672c0906bb2"


def send_msg(phone_number: str, body: str):
    client = Client(account_sid, auth_token)

    client.messages.create(to=f"+351{phone_number}", from_="+13192545690", body=body)


def gen_opt_key():
    totp = pyotp.random_base32()
    return totp


def gen_otp_code(key: str):
    totp = pyotp.TOTP(key)
    return totp.now()


def verify_otp_code(key: str, code: str):
    totp = pyotp.TOTP(key)
    return totp.verify(code)