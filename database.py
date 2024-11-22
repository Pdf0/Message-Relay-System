import json
import threading
import time

from server_client import Client, Message


class Database:
    def __init__(self, filename):
        self.filename = filename
        self.data = {}
        self.lock = threading.Lock()
        self.load_from_file()

    def load_from_file(self):
        try:
            with open(self.filename, "r") as f:
                self.data = json.load(f)
                for key in self.data:
                    self.data[key] = Client.from_dict(self.data[key])
        except FileNotFoundError:
            with open(self.filename, "w") as f:
                json.dump({}, f)
            with open(self.filename, "r") as f:
                self.data = json.load(f)
        except json.JSONDecodeError:
            with open(self.filename, "w") as f:
                json.dump({}, f)
            with open(self.filename, "r") as f:
                self.data = json.load(f)

    def save_to_file(self):
        with self.lock:
            with open(self.filename, "w") as f:
                json.dump(self.data, f, default=self.serialize_custom_objects)

    def get(self, key):
        return self.data.get(key)

    def set(self, key, value):
        self.data[str(key)] = value
        self.save_to_file()

    def add_message(self, key, message):
        if self.data.get(key):
            self.data[key].add_message(message)
        else:
            client = Client()
            client.add_message(message)
            self.data[key] = client
        self.save_to_file()

    def pop(self, key):
        pop = self.data.pop(str(key), None)
        self.save_to_file()
        return pop

    def serialize_custom_objects(self, obj):
        if isinstance(obj, (Client, Message)):
            return obj.to_dict()
        return None
