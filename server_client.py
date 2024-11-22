import json
from datetime import datetime


class Client:
    def __init__(self):
        self.messages = []
        self.hashed_password = None
        self.cert = None
        self.two_fa = None
        self.two_fa_key = None
        self.phone_number = None

    def to_json(self):
        return json.dumps(self.to_dict())

    @staticmethod
    def from_json(json_str):
        return Client.from_dict(json.loads(json_str))

    def to_dict(self):
        return {
            "messages": [message.to_dict() for message in self.messages],
            "hashed_password": self.hashed_password,
            "cert": self.cert,
            "two_fa": self.two_fa,
            "two_fa_key": self.two_fa_key,
            "phone_number": self.phone_number,
        }

    @staticmethod
    def from_dict(data):
        client = Client()
        client.messages = [Message.from_dict(msg) for msg in data["messages"]]
        client.hashed_password = data["hashed_password"]
        client.cert = data["cert"]
        client.two_fa = data["two_fa"]
        client.two_fa_key = data["two_fa_key"]
        client.phone_number = data["phone_number"]
        return client

    def add_message(self, message):
        message.add_num(len(self.messages))
        self.messages.append(message)

    def get_messages(self):
        return self.messages

    def get_message(self, num):
        for message in self.messages:
            if message.num == num:
                return message
        return None


class Message:
    def __init__(self, sender, message, timestamp, key, signature, tsa_signature, num=None, is_read=False):
        self.num = num
        self.sender = sender
        self.message = message
        self.timestamp = timestamp
        self.is_read = is_read
        self.key = key
        self.signature = signature
        self.tsa_signature = tsa_signature

    def to_dict(self):
        return {
            "num": self.num,
            "sender": self.sender,
            "message": self.message,
            "timestamp": self.timestamp,
            "key": self.key,
            "signature": self.signature,
            "tsa_signature": self.tsa_signature,
            "is_read": self.is_read
        }

    @staticmethod
    def from_dict(data):
        return Message(
            data["sender"],
            data["message"],
            data["timestamp"],
            data["key"],
            data["signature"],
            data["tsa_signature"],
            data["num"],
            data["is_read"]
        )

    def to_json(self):
        return json.dumps(self.to_dict())

    @staticmethod
    def from_json(json_str):
        return Message.from_dict(json.loads(json_str))

    def add_num(self, num):
        self.num = str(num)

    def read(self):
        self.is_read = True
