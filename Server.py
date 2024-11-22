# Código baseado em https://docs.python.org/3.6/library/asyncio-stream.html#tcp-echo-client-using-streams
import asyncio
import base64 as b64
import logging
import os
import sys
import json
from datetime import datetime
from logging.handlers import RotatingFileHandler

import protocol
import utils
from cert_validator import CertificateValidator
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import dh, padding
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.x509 import Certificate

import protocol
import two_fa_msg
import utils
from cert_validator import CertificateValidator
from database import Database
from protocol import Packet
from server_client import Client, Message

p = 0xFFFFFFFFFFFFFFFFC90FDAA22168C234C4C6628B80DC1CD129024E088A67CC74020BBEA63B139B22514A08798E3404DDEF9519B3CD3A431B302B0A6DF25F14374FE1356D6D51C245E485B576625E7EC6F44C42E9A637ED6B0BFF5CB6F406B7EDEE386BFB5A899FA5AE9F24117C4B1FE649286651ECE45B3DC2007CB8A163BF0598DA48361C55D39A69163FA8FD24CF5F83655D23DCA3AD961C62F356208552BB9ED529077096966D670C354E4ABC9804F1746C08CA18217C32905E462E36CE3BE39E772C180E86039B2783A2EC07A28FB5C55DF06F4C52C9DE2BCBF6955817183995497CEA956AE515D2261898FA051015728E5A8AACAA68FFFFFFFFFFFFFFFF
g = 2
conn_cnt = 0
conn_port = 8443
tsa_host = '127.0.0.1'
tsa_conn_port = 8444
max_msg_size = 9999
db = Database("database.json")


class ServerWorker(object):
    """Classe que implementa a funcionalidade do SERVIDOR."""

    def __init__(self, cnt, addr=None):
        """Construtor da classe."""
        self.id = cnt
        self.addr = addr
        self.username = None
        self.restart = False
        self.msg_cnt = 0
        self.dhprivate_key: dh.DHPrivateKey = (
            dh.DHParameterNumbers(p, g).parameters().generate_private_key()
        )
        self.rsa_private_key = None
        self.cert_name = "MSG_SERVER.crt"
        self.cert: Certificate = None
        self.ca_cert: Certificate = None
        self.verifier: CertificateValidator = CertificateValidator()
        self.client_pub_dh_key: dh.DHPublicKey = None
        self.client_cert_name: str = None
        self.client_cert: Certificate = None
        self.aesgcm: AESGCM = None
        self.two_fa_method = None
        self.phone_number = None
        self.two_fa_key = None

        try:
            self.rsa_private_key = serialization.load_pem_private_key(
                open("certs/MSG_SERVER.key", "rb").read(),
                password=None,
            )
            self.cert = x509.load_pem_x509_certificate(
                open("certs/MSG_SERVER.crt", "rb").read()
            )
            self.ca_cert = x509.load_pem_x509_certificate(
                open("certs/MSG_CA.crt", "rb").read()
            )
        except:
            logging.info("Error loading the server's certificates.")
            exit(1)

    async def process(self, msg):
        """Processa uma mensagem (`bytestring`) enviada pelo CLIENTE.
        Retorna a mensagem a transmitir como resposta (`None` para
        finalizar ligação)"""
        self.msg_cnt += 1

        if self.aesgcm:
            msg = utils.decrypt_message(msg, self.aesgcm)
        message = Packet.from_json(msg.decode())

        if message.type == "pub_key":
            self.client_pub_dh_key = serialization.load_pem_public_key(
                b64.b64decode(message.content.encode())
            )

            # Creates the pair of public keys
            dh_pair = utils.join_pair(
                self.dhprivate_key.public_key().public_bytes(
                    encoding=serialization.Encoding.PEM,
                    format=serialization.PublicFormat.SubjectPublicKeyInfo,
                ),
                self.client_pub_dh_key.public_bytes(
                    encoding=serialization.Encoding.PEM,
                    format=serialization.PublicFormat.SubjectPublicKeyInfo,
                ),
            )
            # Generates the signature of the pair of keys
            signature = self.rsa_private_key.sign(
                dh_pair,
                padding.PSS(
                    mgf=padding.MGF1(hashes.SHA256()),
                    salt_length=padding.PSS.MAX_LENGTH,
                ),
                hashes.SHA256(),
            )

            new_msg: Packet = Packet(
                "pub_sign_cert",
                {
                    "pub_key": b64.b64encode(
                        self.dhprivate_key.public_key().public_bytes(
                            encoding=serialization.Encoding.PEM,
                            format=serialization.PublicFormat.SubjectPublicKeyInfo,
                        )
                    ).decode(),
                    "signature": b64.b64encode(signature).decode(),
                    "cert": [
                        b64.b64encode(
                            self.cert.public_bytes(encoding=serialization.Encoding.PEM)
                        ).decode(),
                        self.cert_name,
                    ],
                },
            )

            return new_msg.to_json().encode()

        elif message.type == "sign_cert":
            self.client_cert = x509.load_pem_x509_certificate(
                b64.b64decode(message.content["cert"][0].encode())
            )
            self.client_cert_name = message.content["cert"][1]

            # Verifies the certificate
            if not self.verifier.validate_certificate(
                self.client_cert, self.client_cert_name.split("/")[-1].split(".")[0]
            ):
                print(f"[{self.id}] Received invalid certificate.")
                return

            # Verifies the signature
            if not utils.verify_signature(
                b64.b64decode(message.content["signature"].encode()),
                self.client_cert.public_key(),
                utils.join_pair(
                    self.client_pub_dh_key.public_bytes(
                        encoding=serialization.Encoding.PEM,
                        format=serialization.PublicFormat.SubjectPublicKeyInfo,
                    ),
                    self.dhprivate_key.public_key().public_bytes(
                        encoding=serialization.Encoding.PEM,
                        format=serialization.PublicFormat.SubjectPublicKeyInfo,
                    ),
                ),
            ):
                logging.info(f"Invalid signature from client [{self.id}]".format)
                return

            shared_key = self.dhprivate_key.exchange(self.client_pub_dh_key)

            key = HKDF(
                algorithm=hashes.SHA256(),
                length=32,
                salt=None,
                info=b"handshake data",
            ).derive(shared_key)

            self.aesgcm = AESGCM(key)
            new_msg = Packet("conn_success", None)

            logging.info(f"Connection established successfully with client [{self.id}]")

            return new_msg.to_json().encode()

        elif message.type == "ask_cert":

            client: Client = db.get(message.content)
            if client:
                new_msg = protocol.create_message("client_cert", client.cert)
                logging.info(
                    f"[{message.content}]'s certificate sent to client [{self.username}]"
                )
            else:
                new_msg = protocol.create_message(
                    "msg_error", "Invalid message recipient"
                )
                logging.info(f"Invalid message recipient from client [{self.username}]")

        elif message.type == "send":
            # Create the Message
            if db.get(message.content["to"]):

                message_hash = utils.calculate_message_hash(message.content["message"].encode())
                timestamp, tsa_signature = await request_timestamp(message_hash)

                msg_to_store = Message(
                    self.username,
                    message.content["message"],
                    timestamp,
                    message.content["key"],
                    message.content["signature"],
                    tsa_signature,
                )
                # Store the Message in the database (in the sender's instance)
                db.add_message(message.content["to"], msg_to_store)

                new_msg = protocol.create_message(
                    "msg_sent", "Message sent successfully"
                )
                logging.info(
                    f"Message from client [{self.username}] sent successfully to client [{message.content['to']}]"
                )
            else:
                new_msg = protocol.create_message(
                    "msg_error", "Invalid message recipient"
                )
                logging.info(f"Invalid message recipient from client [{self.username}]")

        elif message.type == "askqueue":

            db_result: Client = db.get(self.username)
            messages = db_result.get_messages() if db_result else None

            if messages:
                unread_messages = [
                    message for message in messages if not message.is_read
                ]
                if len(unread_messages) > 0:
                    msgs = []
                    for msg in unread_messages:
                        sender_cert = db.get(msg.sender).cert
                        msgs += [
                            {
                                "num": msg.num,
                                "sender": msg.sender,
                                "message": msg.message,
                                "timestamp": msg.timestamp,
                                "key": msg.key,
                                "signature": msg.signature,
                                "cert": sender_cert,
                                "tsa_signature": msg.tsa_signature
                            }
                        ]

                    new_msg = protocol.create_message("msgs", msgs)
                else:
                    new_msg = protocol.create_message("msg_error", "Empty queue")
            else:
                new_msg = protocol.create_message("msg_error", "Empty queue")
            logging.info(f"Client [{self.username}] asked for messages in queue")

        elif message.type == "getmsg":

            user = db.get(self.username)
            message = user.get_message(message.content) if user else None
            if message:
                sender_cert = db.get(message.sender).cert
                new_msg = protocol.create_message(
                    "msg",
                    {
                        "sender": message.sender,
                        "message": message.message,
                        "timestamp": message.timestamp,
                        "key": message.key,
                        "signature": message.signature,
                        "cert": sender_cert,
                        "tsa_signature": message.tsa_signature
                    },
                )
                if not message.is_read:
                    logging.info(
                        f"Received a request for a message from client [{self.username}]"
                    )
                    message.read()
                    db.save_to_file()

                else:
                    logging.info(f"Old message request from [{self.username}]")
            else:
                new_msg = protocol.create_message(
                    "msg_error", "Invalid message request"
                )
                logging.info(f"Invalid message request from [{self.username}]")

        elif message.type == "getallmsgs":
            user = db.get(self.username)
            messages = user.get_messages()

            if messages:
                msgs = []
                for msg in messages:
                    sender_cert = db.get(msg.sender).cert
                    msgs += [
                        {
                            "num": msg.num,
                            "sender": msg.sender,
                            "message": msg.message,
                            "timestamp": msg.timestamp,
                            "key": msg.key,
                            "signature": msg.signature,
                            "cert": sender_cert,
                            "tsa_signature": msg.tsa_signature
                        }
                    ]
                new_msg = protocol.create_message("msgs", msgs)
            else:
                new_msg = protocol.create_message("msg_error", "Empty queue")
            logging.info(f"Client [{self.username}] asked for all messages")

        elif message.type == "getmsgsfrom":
            user = db.get(self.username)
            messages = user.get_messages()

            if messages:
                msgs = []
                for msg in messages:
                    if msg.sender == message.content:
                        sender_cert = db.get(msg.sender).cert
                        msgs += [
                            {
                                "num": msg.num,
                                "sender": msg.sender,
                                "message": msg.message,
                                "timestamp": msg.timestamp,
                                "key": msg.key,
                                "signature": msg.signature,
                                "cert": sender_cert,
                                "tsa_signature": msg.tsa_signature
                            }
                        ]
                new_msg = protocol.create_message("msgs", msgs)
            else:
                new_msg = protocol.create_message("msg_error", "Empty queue")
            logging.info(
                f"Client [{self.username}] asked for all messages from [{message.content}]"
            )

        elif message.type == "register_attempt":
            # If username already exists
            if db.get(message.content["username"]):
                # Send an error message
                print(db.get(message.content["username"]))
                new_msg = protocol.create_message(
                    "register_error", "Username already exists."
                )
                logging.info(
                    f"Client [{self.id}] tried to register with an existing username ({message.content['username']})."
                )
            else:
                new_client = Client()
                # Store the new client in the database
                hashed_password = message.content["password"]
                new_client.hashed_password = hashed_password
                db.set(message.content["username"], new_client)
                # Set the username of the client
                self.username = message.content["username"]
                # Send the success message
                new_msg = protocol.create_message(
                    "register_success", f"\nWelcome {self.username}."
                )
                self.restart = True
                logging.info(
                    f"Client [{self.id}] registered successfully with username '{message.content['username']}'."
                )

        elif message.type == "register_success":
            user: Client = db.get(self.username)
            user.cert = message.content

            db.set(self.username, user)

            new_msg = protocol.create_message("register_done", None)

        elif message.type == "login_attempt":
            # If the username doesn't exist
            if not db.get(message.content["username"]):
                # Send an error message
                new_msg = protocol.create_message(
                    "msg_error", "Username doesn't exist."
                )
                logging.info(
                    f"Client [{self.id}] tried to log in with a non-existing username ({message.content['username'].encode()})."
                )
            else:
                # Send the login credentials for the client to check the password on his side

                new_msg = protocol.create_message(
                    "login_creds",
                    {
                        "username": message.content["username"],
                        "password": db.get(message.content["username"]).hashed_password,
                    },
                )

        elif message.type == "login_success":
            logging.info(
                f"Client [{self.id}] logged in successfully with username '{message.content['username']}'."
            )
            self.username = message.content["username"]

            user = db.get(self.username)
            self.two_fa_method = user.two_fa
            self.phone_number = user.phone_number
            self.two_fa_key = user.two_fa_key

            if user.two_fa == "totp":
                new_msg = protocol.create_message(
                    "login_totp",
                    None
                )

            elif user.two_fa == "sms":
                code = two_fa_msg.gen_otp_code(user.two_fa_key)
                two_fa_msg.send_msg(user.phone_number, f"This is your code: {code}")

                new_msg = protocol.create_message(
                    "2fa_sms",
                    {
                        "code": code,
                        "phone_number": user.phone_number,
                        "message": f"Welcome back {self.username}.",
                    },
                )
            else:
                new_msg = protocol.create_message(
                    "login_success", f"Welcome back {self.username}."
                )

        elif message.type == "2fa_request":

            if message.content["option"] == "totp":
                self.two_fa_key = two_fa_msg.gen_opt_key()
                new_msg = protocol.create_message(
                    "2fa_totp",
                    {
                        "key": self.two_fa_key
                    }
                )

            elif message.content["option"] == "sms":
                self.two_fa_key = two_fa_msg.gen_opt_key()
                code = two_fa_msg.gen_otp_code(self.two_fa_key)
                two_fa_msg.send_msg(
                    message.content["phone_number"], f"This is your code: {code}"
                )
                new_msg = protocol.create_message(
                    "2fa_sms",
                    {
                        "code": code,
                        "phone_number": message.content["phone_number"],
                        "message": "Two Factor Authentication activated through SMS",
                    },
                )
                logging.info(f"2FA SMS request from [{self.username}]")

        elif message.type == "2fa_totp_code":
            client_code = message.content["code"]
            if two_fa_msg.verify_otp_code(self.two_fa_key, client_code):
                if self.two_fa_method != "totp":

                    self.two_fa_method = "totp"

                    user = db.get(self.username)
                    user.two_fa = "totp"
                    user.two_fa_key = self.two_fa_key

                    db.set(self.username, user)

                    new_msg = protocol.create_message("2fa_done", {"option": "totp", "message": "Two Factor Authentication activated through TOTP."})
                    logging.info(f"2FA TOTP activation successfull from [{self.username}]")

                else:
                    logging.info(f"Client [{self.username}] logged in using TOTP.")
                new_msg = protocol.create_message("2fa_done", {"option": "totp", "message": f"Welcome back {self.username}."})

            else:
                new_msg = protocol.create_message("msg_error", "Invalid code.")
                logging.info(f"Invalid TOTP code from [{self.username}]")

        elif message.type == "2fa_success":

            if message.content["option"] == "sms":
                if self.two_fa_method != "sms":
                    self.two_fa_method = "sms"
                    self.phone_number = message.content["phone_number"]

                    logging.info(f"2FA SMS activation successfull from [{self.username}]")

                    user = db.get(self.username)

                    user.two_fa = "sms"
                    user.two_fa_key = self.two_fa_key
                    user.phone_number = self.phone_number

                    db.set(self.username, user)
                else:
                    logging.info(f"Client [{self.username}] logged in using SMS.")

                new_msg = protocol.create_message("2fa_done", {"option": "sms"})
        else:
            logging.info(f"Invalid request from [{self.id}]")
            # Send an error message
            new_msg = protocol.create_message("msg_error", "Invalid request")

        if new_msg:
            new_msg = new_msg.to_json().encode()
        if self.aesgcm:
            new_msg = utils.encrypt_message(new_msg, self.aesgcm)

        return new_msg

async def request_timestamp(data):
    reader, writer = await asyncio.open_connection(tsa_host, tsa_conn_port)
    try:
        writer.write(data)
        await writer.drain()

        response_data = await reader.read()
        response = json.loads(response_data.decode())
        return response['timestamp'], response['signature']
    finally:
        writer.close()
        await writer.wait_closed()



#
#
# Funcionalidade Cliente/Servidor
#
# obs: não deverá ser necessário alterar o que se segue
#


async def handle_echo(reader, writer):
    global conn_cnt
    conn_cnt += 1
    addr = writer.get_extra_info("peername")
    srvwrk = ServerWorker(conn_cnt, addr)
    try:
        data = await reader.read(max_msg_size)
        while True:
            if not data:
                continue
            if data[:1] == b"\n":
                break
            data = await srvwrk.process(data)
            writer.write(data)
            await writer.drain()
            data = await reader.read(max_msg_size)

        logging.info("Connection from client [{}]".format(srvwrk.id) + " ended")
        writer.close()

    except ConnectionResetError as e:
        logging.info(f"ConnectionResetError occurred: {e}")
        writer.close()

    except Exception as e:
        logging.info(f"Some error occurred: {e.__repr__()}")
        writer.close()


def run_server():
    loop = asyncio.new_event_loop()
    coro = asyncio.start_server(handle_echo, "127.0.0.1", conn_port)
    server = loop.run_until_complete(coro)
    logging.info("Serving on {}".format(server.sockets[0].getsockname()))
    try:
        loop.run_forever()
    except KeyboardInterrupt:
        logging.info("\nServer closed manually.")
        exit(0)
    except Exception as e:
        logging.error(f"\nServer closed due to { e.__repr()}")
        exit(1)

    # Close the server
    server.close()
    loop.run_until_complete(server.wait_closed())
    loop.close()
    logging.info("Server closed")


logging.basicConfig(
    filename="server.log",
    level=logging.INFO,
    format="%(asctime)s - %(levelname)s - %(message)s",
)
console_handler = logging.StreamHandler(sys.stdout)
console_handler.setLevel(logging.INFO)
console_handler.setFormatter(
    logging.Formatter("%(asctime)s - %(levelname)s - %(message)s")
)
logging.getLogger().addHandler(console_handler)

run_server()
