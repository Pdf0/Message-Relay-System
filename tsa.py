import asyncio
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives import hashes
import base64
import time
import json
import logging

conn_cnt = 0
conn_port = 8444
max_msg_size = 9999

class TSA:
    def __init__(self):

        try:
            with open("TSA_priv.key", "rb") as file:
                self.private_key = serialization.load_pem_private_key(
                    file.read(),
                    password=None
                )
                self.public_key = self.private_key.public_key()

        except FileNotFoundError:
            self.private_key = rsa.generate_private_key(
                public_exponent=65537,
                key_size=2048
            )
            self.public_key = self.private_key.public_key()

            with open('TSA_priv.key', 'wb') as file:
                file.write(self.private_key.private_bytes(
                    encoding=serialization.Encoding.PEM,
                    format=serialization.PrivateFormat.TraditionalOpenSSL,
                    encryption_algorithm=serialization.NoEncryption()
                )
            )
            with open('TSA_pub.key', 'wb') as file:
                file.write(self.public_key.public_bytes(
                    encoding=serialization.Encoding.PEM,
                    format=serialization.PublicFormat.SubjectPublicKeyInfo
                ))

    def generate_timestamp(self):
        timestamp = time.time()
        return timestamp

    def sign_data(self, data):
        signature = self.private_key.sign(
            data,
            padding.PSS(
                mgf=padding.MGF1(hashes.SHA256()),
                salt_length=padding.PSS.MAX_LENGTH
            ),
            hashes.SHA256()
        )
        return base64.b64encode(signature).decode()

    def timestamp_and_sign(self, message):
        timestamp = self.generate_timestamp()

        hashed_message_base64 = base64.b64encode(message).decode()

        data_to_sign = json.dumps({'message': hashed_message_base64, 'timestamp': timestamp})
        signature = self.sign_data(data_to_sign.encode())

        stamped_data = {'data': hashed_message_base64, 'timestamp': timestamp, 'signature': signature}

        return stamped_data

    async def handle_echo(self, reader, writer):
        data = await reader.read(max_msg_size)

        stamped_data = self.timestamp_and_sign(data)
        response = json.dumps(stamped_data).encode()

        writer.write(response)
        await writer.drain()

        print("Packet timestamped successfully")
        writer.close()

    def start_tsa(self):
        loop = asyncio.new_event_loop()
        coroutine = asyncio.start_server(self.handle_echo, "127.0.0.1", conn_port)
        server = loop.run_until_complete(coroutine)
        print(f"Listening on... 127.0.0.1:{conn_port}...")
        try:
            loop.run_forever()
        except KeyboardInterrupt:
            logging.info("\nTSA closed manually.")
            exit(0)
        except Exception as e:
            logging.error(f"\nTSA closed due to { e.__repr__()}")
            exit(1)
        finally:
            server.close()
        loop.run_until_complete(server.wait_closed())
        loop.close()
        logging.info("TSA closed")

if __name__ == "__main__":
    tsa = TSA()

    print("TSA initiating...")
    tsa.start_tsa()
