import json

# Types of packets:
#   - pub_key: public key
#   - pub_sign_cert: public key, signature and certificate
#   - sign_cert: signature and certificate
#   - client_cert: another client's certificate
#   - conn_success: connection successful
#   - send: send a message to a user
#   - askqueue: ask for the queue of messages
#   - getmsg: get a message from the queue
#   - getallmsgs: get all messages from the queue
#   - getmsgsfrom: get all messages from a user
#   - msg_sent: message sent successfully
#   - msg: message from the queue
#   - msgs: messages from the queue
#   - register_attempt: attempt to register
#   - register_success: registration successful
#   - register_done: registration done
#   - register_error: some error occurred during registration
#   - login_attempt: attempt to login
#   - login_creds: login credentials
#   - login_success: login successful
#   - login_totp: login with totp
#   - 2fa_request: request for 2fa
#   - 2fa_success: 2fa successful
#   - 2fa_totp_code: totp code
#   - 2fa_sms: sms code
#   - 2fa_totp: totp code
#   - 2fa_done: 2fa done
#   - msg_error: some error occurred


class Packet:
    def __init__(self, type, content):
        self.type = type
        self.content = content

    def __str__(self):
        return f"Type: {self.type}\nContent: {self.content}"

    def to_dict(self):
        return (
            {"type": self.type, "content": self.content}
            if not isinstance(self.content, bytes)
            else {"type": self.type, "content": self.content.decode("utf-8")}
        )

    def from_dict(data):
        return Packet(data["type"], data["content"])

    def to_json(self):
        return json.dumps(self.to_dict())

    def from_json(json_str):
        return Packet.from_dict(json.loads(json_str))


def create_message(type, content=None):
    return Packet(type, content)
