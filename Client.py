# Código baseado em https://docs.python.org/3.6/library/asyncio-stream.html#tcp-echo-client-using-streams
import argparse
import asyncio
import base64 as b64
import getpass
import socket
import traceback
import os
import json
from datetime import datetime
import keystore_generator
import protocol
import utils
from cert_validator import CertificateValidator
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import dh, padding
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.backends import default_backend
from cryptography.x509 import Certificate
from protocol import Packet
from server_client import Message

p = 0xFFFFFFFFFFFFFFFFC90FDAA22168C234C4C6628B80DC1CD129024E088A67CC74020BBEA63B139B22514A08798E3404DDEF9519B3CD3A431B302B0A6DF25F14374FE1356D6D51C245E485B576625E7EC6F44C42E9A637ED6B0BFF5CB6F406B7EDEE386BFB5A899FA5AE9F24117C4B1FE649286651ECE45B3DC2007CB8A163BF0598DA48361C55D39A69163FA8FD24CF5F83655D23DCA3AD961C62F356208552BB9ED529077096966D670C354E4ABC9804F1746C08CA18217C32905E462E36CE3BE39E772C180E86039B2783A2EC07A28FB5C55DF06F4C52C9DE2BCBF6955817183995497CEA956AE515D2261898FA051015728E5A8AACAA68FFFFFFFFFFFFFFFF
g = 2
conn_port = 8443
max_msg_size = 9999
user_keystore = None


class Client:
    """Classe que implementa a funcionalidade de um CLIENTE."""

    def __init__(self, sckt=None):
        """Construtor da classe."""
        self.sckt = sckt
        self.msg_cnt = 0
        self.dhprivate_key: dh.DHPrivateKey = (
            dh.DHParameterNumbers(p, g).parameters().generate_private_key()
        )
        self.username = None
        self.temp_password = None
        self.logged_in = False
        self.rsa_private_key = None
        self.cert_name: str = None
        self.cert: Certificate = None
        self.ca_cert: Certificate = None
        self.verifier: CertificateValidator = CertificateValidator()
        self.server_dh_pub_key: dh.DHPublicKey = None
        self.server_cert_name: str = None
        self.server_cert: Certificate = None
        self.aesgcm: AESGCM = None
        self.message_to_send = None
        self.two_fa_code = False

        if user_keystore:
            credentials_packet = get_credentials(self, "login_attempt")
            self.username = credentials_packet.content["username"]
            password = self.temp_password

            try:
                self.rsa_private_key, self.cert, self.ca_cert = utils.get_userdata(
                    user_keystore, password
                )
                self.cert_name = os.path.basename(user_keystore).split(".")[0] + ".crt"
            except:
                print("Error loading user keystore")
                return -1

            if not self.verifier.validate_certificate(self.cert, self.username):
                print("Invalid certificate")
                return -1
        else:
            self.rsa_private_key, self.cert, self.ca_cert = utils.get_userdata(
                "certs/default.p12"
            )
            self.cert_name = "default.crt"

    def process(self, msg=b""):
        """Processa uma mensagem (`bytestring`) enviada pelo SERVIDOR.
        Retorna a mensagem a transmitir como resposta (-1 para
        finalizar ligação)"""
        self.msg_cnt += 1
        #
        # ALTERAR AQUI COMPORTAMENTO DO CLIENTE
        #
        if msg:
            if self.aesgcm:
                msg = utils.decrypt_message(msg, self.aesgcm)
            message = Packet.from_json(msg.decode())

            if message.type == "pub_sign_cert":
                self.server_dh_pub_key = serialization.load_pem_public_key(
                    b64.b64decode(message.content["pub_key"].encode())
                )
                self.server_cert = x509.load_pem_x509_certificate(
                    b64.b64decode(message.content["cert"][0].encode())
                )
                self.server_cert_name = message.content["cert"][1]

                # Verifies the certificate
                if not self.verifier.validate_certificate(
                    self.server_cert, self.server_cert_name.split("/")[-1].split(".")[0]
                ):
                    print("Received invalid certificate.")
                    return -1

                # Verifies the signature
                if not utils.verify_signature(
                    b64.b64decode(message.content["signature"].encode()),
                    self.server_cert.public_key(),
                    utils.join_pair(
                        self.server_dh_pub_key.public_bytes(
                            encoding=serialization.Encoding.PEM,
                            format=serialization.PublicFormat.SubjectPublicKeyInfo,
                        ),
                        self.dhprivate_key.public_key().public_bytes(
                            encoding=serialization.Encoding.PEM,
                            format=serialization.PublicFormat.SubjectPublicKeyInfo,
                        ),
                    ),
                ):
                    print("Invalid signature")
                    return -1

                signature = self.rsa_private_key.sign(
                    utils.join_pair(
                        self.dhprivate_key.public_key().public_bytes(
                            encoding=serialization.Encoding.PEM,
                            format=serialization.PublicFormat.SubjectPublicKeyInfo,
                        ),
                        self.server_dh_pub_key.public_bytes(
                            encoding=serialization.Encoding.PEM,
                            format=serialization.PublicFormat.SubjectPublicKeyInfo,
                        ),
                    ),
                    padding.PSS(
                        mgf=padding.MGF1(hashes.SHA256()),
                        salt_length=padding.PSS.MAX_LENGTH,
                    ),
                    hashes.SHA256(),
                )

                new_msg = (
                    protocol.create_message(
                        "sign_cert",
                        {
                            "signature": b64.b64encode(signature).decode(),
                            "cert": [
                                b64.b64encode(
                                    self.cert.public_bytes(
                                        encoding=serialization.Encoding.PEM,
                                    )
                                ).decode(),
                                self.cert_name,
                            ],
                        },
                    )
                    .to_json()
                    .encode()
                )
            elif message.type == "client_cert":
                client_cert = x509.load_pem_x509_certificate(
                    b64.b64decode(message.content.encode())
                )

                if not self.verifier.validate_certificate(
                    client_cert, self.message_to_send["to"]
                ):
                    print("Invalid recipient's certificate.")
                    return -1
                
                key = utils.generate_hkdf_key(32)
                aesgcm = AESGCM(key)
                encrypted_message = utils.encrypt_message(json.dumps(self.message_to_send["message"]).encode(), aesgcm)

                signature = self.rsa_private_key.sign(
                    encrypted_message,
                    padding.PSS(
                        mgf=padding.MGF1(hashes.SHA256()),
                        salt_length=padding.PSS.MAX_LENGTH,
                    ),
                    hashes.SHA256(),
                )

                key = client_cert.public_key().encrypt(
                    key,
                    padding.OAEP(
                        mgf=padding.MGF1(algorithm=hashes.SHA256()),
                        algorithm=hashes.SHA256(),
                        label=None,
                    ),
                )
                new_msg = (
                    protocol.create_message(
                        "send",
                        {
                            "to": self.message_to_send["to"],
                            "message": b64.b64encode(encrypted_message).decode(),
                            "key": b64.b64encode(key).decode(),
                            "signature": b64.b64encode(signature).decode(),
                        },
                    )
                )

            elif message.type == "msg_sent":
                print(message.content)

            elif message.type == "msgs":
                print()
                print(
                    "{:<8s} {:<12s} {:<20s} {:<12s}".format(
                        "<NUM>", "<SENDER>", "<TIME>", "<SUBJECT>"
                    )
                )
                for msg in message.content:

                    if not self.verifier.validate_certificate(
                        x509.load_pem_x509_certificate(
                            b64.b64decode(msg["cert"].encode())
                        ),
                        msg["sender"],
                    ):
                        print("Invalid certificate")
                        return -1

                    if not utils.verify_signature(
                        b64.b64decode(msg["signature"].encode()),
                        x509.load_pem_x509_certificate(
                            b64.b64decode(msg["cert"].encode())
                        ).public_key(),
                        b64.b64decode(msg["message"].encode())
                    ):
                        print("Invalid signature")
                        return -1

                    try:
                        key = self.rsa_private_key.decrypt(
                            b64.b64decode(msg["key"].encode()),
                            padding.OAEP(
                                mgf=padding.MGF1(algorithm=hashes.SHA256()),
                                algorithm=hashes.SHA256(),
                                label=None,
                            ),
                        )
                    except:
                        print("Error decrypting message")
                        return -1

                    aesgcm = AESGCM(key)
                    content = json.loads(utils.decrypt_message(b64.b64decode(msg["message"].encode()), aesgcm).decode())

                    if check_timestamp(msg["message"], msg["timestamp"], msg["tsa_signature"]):

                        datetime_timestamp = datetime.fromtimestamp(msg["timestamp"])

                        formatted_time = datetime_timestamp.strftime("%Y-%m-%d %H:%M")


                        print(
                            "{:<8s} {:<12s} {:<20s} {:<12s}".format(
                                str(msg["num"]),
                                msg["sender"],
                                formatted_time,
                                content["subject"]
                            )
                        )

                    else:
                        print("TSA signature not verified successfully")

            elif message.type == "msg":
                message = message.content

                if not self.verifier.validate_certificate(
                        x509.load_pem_x509_certificate(
                            b64.b64decode(message["cert"].encode())
                        ),
                        message["sender"],
                    ):
                        print("Invalid certificate")
                        return -1

                if not utils.verify_signature(
                        b64.b64decode(message["signature"].encode()),
                        x509.load_pem_x509_certificate(
                            b64.b64decode(message["cert"].encode())
                        ).public_key(),
                        b64.b64decode(message["message"].encode())
                    ):
                        print("Invalid signature")
                        return -1

                try:
                    key = self.rsa_private_key.decrypt(
                        b64.b64decode(message["key"].encode()),
                        padding.OAEP(
                            mgf=padding.MGF1(algorithm=hashes.SHA256()),
                            algorithm=hashes.SHA256(),
                            label=None,
                        ),
                    )
                except:
                    print("Error decrypting message")
                    return -1


                aesgcm = AESGCM(key)
                content = json.loads(utils.decrypt_message(b64.b64decode(message["message"].encode()), aesgcm).decode())


                if check_timestamp(message["message"], message["timestamp"], message["tsa_signature"]):

                    datetime_timestamp = datetime.fromtimestamp(message["timestamp"])

                    formatted_time = datetime_timestamp.strftime("%Y-%m-%d %H:%M")


                    print(f"\n\nFrom: {message["sender"]}")
                    print(
                        f"Sended at: {formatted_time}"
                    )
                    print(f"Subject: {content["subject"]}")
                    print("Message:\n")
                    content_lines = [
                        content["body"][i : i + 80]
                        for i in range(0, len(content["body"]), 80)
                    ]
                    indented_content = ["    " + line for line in content_lines]
                    print("\n".join(indented_content))
                    print()
                else:
                    print("TSA signature not verified successfully")

            elif message.type == "conn_success":
                shared_key = self.dhprivate_key.exchange(self.server_dh_pub_key)
                key = HKDF(
                    algorithm=hashes.SHA256(),
                    length=32,
                    salt=None,
                    info=b"handshake data",
                ).derive(shared_key)

                self.aesgcm = AESGCM(key)

                print("Connection established successfully")

                if not user_keystore:
                    new_msg = self.register()
                    self.username = new_msg.content["username"]
                else:
                    new_msg = protocol.create_message(
                        "login_attempt",
                        {
                            "username": self.username,
                            "password": self.temp_password,
                        },
                    )

            elif message.type == "register_success":
                self.rsa_private_key, self.cert, self.ca_cert = (
                    keystore_generator.generate_keystore(
                        self.username, self.temp_password
                    )
                )
                print(
                    message.content
                    + "\nKeystore generated with the following name: "
                    + self.username
                    + ".p12 and protected by the password you provided."
                )

                new_msg = protocol.create_message(
                    "register_success",
                    b64.b64encode(
                        self.cert.public_bytes(encoding=serialization.Encoding.PEM)
                    ).decode(),
                )

            elif message.type == "register_done":            
                self.logged_in = True
                print("\nType 'help' for help")

            elif message.type == "register_error":
                print(f"\n{message.content}\n")
                new_msg = self.register()
                self.username = new_msg.content["username"]

            elif message.type == "login_creds":
                if utils.check_password(
                    self.temp_password, message.content["password"]
                ):
                    new_msg = protocol.create_message(
                        "login_success",
                        {
                            "username": message.content["username"],
                            "password": self.temp_password,
                        },
                    )
                    self.temp_password = None
                else:
                    print("\nInvalid password\n")
                    self.temp_password = None
                    return -1

            elif message.type == "login_success":
                self.logged_in = True
                print(f"\n{message.content}\n")
                print("Type 'help' for help")

            elif message.type == "2fa_sms":

                print("Enter the code you received by SMS")
                code = input("Code: ")

                if code == message.content["code"]:
                    new_msg = protocol.create_message("2fa_success", {"option": "sms", "phone_number": message.content["phone_number"]})

                    print(message.content["message"])
                else:
                    print("Invalid code")

                self.two_fa_code = True

            elif message.type == "2fa_totp":
                key = message.content["key"]
                utils.save_to_file(f"otp_keys/{self.username}.txt", key)
                print(f"Your 2fa key was saved in otp_keys/{self.username}.txt.")
                print("Please go to your authentication app and use this key to finish the authentication process.\n")
                print("Enter the code from your authentication app")
                code = input("Code: ")

                new_msg = protocol.create_message(
                    "2fa_totp_code",
                    {
                        "code": code
                    }
                )
                self.two_fa_code = True

            elif message.type == "login_totp":
                print("Enter the code from your authentication app")
                code = input("Code: ")

                new_msg = protocol.create_message(
                    "2fa_totp_code",
                    {
                        "code": code
                    }
                )
                self.two_fa_code = True

            elif message.type == "2fa_done":
                if message.content["option"] == "totp":
                    print(message.content["message"])
                self.two_fa_code = False
                self.logged_in = True

            elif message.type == "msg_error":
                print(f"\n{message.content}")
                if message.content == "Invalid code.":
                    return -1

            else:
                print("Received an invalid message or still not implemented!")
        else:
            new_msg = (
                protocol.create_message(
                    "pub_key",
                    b64.b64encode(
                        self.dhprivate_key.public_key().public_bytes(
                            encoding=serialization.Encoding.PEM,
                            format=serialization.PublicFormat.SubjectPublicKeyInfo,
                        )
                    ).decode()
                )
                .to_json()
                .encode()
            )


        if self.aesgcm:
            if self.logged_in and not self.message_to_send and not self.two_fa_code:
                print("\nInput request to send (empty to finish)")
                try:
                    new_msg = input("> ")
                except KeyboardInterrupt:
                    return -1

                new_msg = parse_input(self, new_msg)

            else:
                self.message_to_send = None

            if new_msg is not None:
                if new_msg != -1:
                    new_msg = new_msg.to_json().encode()
                    new_msg = utils.encrypt_message(new_msg, self.aesgcm)
                else:
                    return -1
                
        return new_msg

    def register(self):
        print("\nRegister")
        new_msg = self.get_credentials("register_attempt")
        return new_msg

    def get_credentials(self, type) -> Packet:
        username = input("\nUsername: ")
        password = getpass.getpass("Password: ")
        self.temp_password = password
        hashed_password = utils.hash_password(password)
        msg = protocol.create_message(
            type, {"username": username, "password": hashed_password}
        )

        return msg

def parse_input(client: Client, msg):
    if not msg:
        return -1
    parsed_msg = msg.split()
    command = parsed_msg[0].lower()
    if command == "send":
        if len(parsed_msg) != 3:
            print("Invalid command format! Usage: send <UID> <SUBJECT>")
            return None

        body = input("\nEnter your message: ")
        if len(body) > 1000:
            print("Message too long! Max 1000 characters!")
            return None

        recipient = parsed_msg[1]
        subject = " ".join(parsed_msg[2:])
        content = {"to": recipient, "message": {"subject": subject, "body": body}}
        client.message_to_send = content
        return protocol.create_message("ask_cert", parsed_msg[1])

    elif command == "askqueue":
        if len(parsed_msg) != 1:
            print("Invalid command format! Usage: askqueue")
            return None
        return protocol.create_message("askqueue", "")
    elif command == "getmsg":
        if len(parsed_msg) != 2:
            print("Invalid command format! Usage: getmsg <NUM>")
            return None
        return protocol.create_message("getmsg", parsed_msg[1])
    elif command == "getallmsgs":
        if len(parsed_msg) != 1:
            print("Invalid command format! Usage: getallmsgs")
            return None
        return protocol.create_message("getallmsgs", "")
    elif command == "getmsgsfrom":
        if len(parsed_msg) != 2:
            print("Invalid command format! Usage: getmsgsfrom <USERNAME>")
            return None
        return protocol.create_message("getmsgsfrom", parsed_msg[1])

    elif command == "2fa":
        if len(parsed_msg) != 1:
            print("Invalid command format! Usage: 2fa")
            return None
        option = two_factor_auth_menu()

        if option == "1":
            print("\nTwo Factor Authentication - TOTP")
            return protocol.create_message("2fa_request", {"option": "totp"})

        elif option == "2":
            print("Two Factor Authentication - SMS")
            phone_number = input("Please enter your phone number: ")

            return protocol.create_message("2fa_request", {"option": "sms", "phone_number": phone_number})


    elif command == "help":
        if len(parsed_msg) != 1:
            print("Invalid command format! Usage: help")
            return None
        print(
            """Available commands:
        send <USERNAME> <SUBJECT> - Send a message to a user. Subject can include spaces
        askqueue - Ask for the queue of messages
        getmsg <NUM> - Get a message from the queue
        getallmsgs - Get all messages
        getmsgsfrom <USERNAME> - Get all messages from a user
        2fa - Two Factor Authentication menu
        help - Show this help
        exit - Exit the program"""
        )
        return None

    elif command == "exit":
        if len(parsed_msg) != 1:
            print("Invalid command format! Usage: exit")
            return None
        return -1

    else:
        print("Invalid command! Type 'help' for available commands.")
        return None


#
#
# Funcionalidade Cliente/Servidor
#
# obs: não deverá ser necessário alterar o que se segue
#


async def tcp_echo_client():
    reader, writer = await asyncio.open_connection("127.0.0.1", conn_port)
    addr = writer.get_extra_info("peername")
    client = Client(addr)
    try:
        msg = client.process()
        while msg != -1:
            if msg:
                writer.write(msg)
                msg = await reader.read(max_msg_size)
            msg = client.process(msg)
        writer.write(b"\n")

        print("\nSocket closed!")
        writer.close()
    except Exception as e:
        print(f"\nSocket closed due to {e.__repr__()}!")
        traceback.print_exc()
        writer.write(b"\n")
        writer.close()


def run_client():
    asyncio.run(tcp_echo_client())


def get_ca_cert():
    with open("certs/MSG_CA.crt", "rb") as f:
        ca_cert = f.read()
    return ca_cert


def get_credentials(client: Client, type) -> Packet:
    username = input("\nUsername: ")
    password = getpass.getpass("Password: ")
    client.temp_password = password
    hashed_password = utils.hash_password(password)
    msg = protocol.create_message(
        type, {"username": username, "password": hashed_password}
    )

    return msg

def two_factor_auth_menu():
    print("\nTwo Factor Authentication")
    print("You can only have one 2FA method active at a time, if you active one, the other will be deactivated.\n")
    print("1 - Use TOTP (Recomended)")
    print("2 - Use SMS")
    print("0 - Exit")
    option = input("Choose an option: ")
    return option

def check_timestamp(message, timestamp, signature):
    with open('TSA_pub.key', 'rb') as file:
        tsa_public_key = serialization.load_pem_public_key(
        file.read(),
        )

    message_hash = utils.calculate_message_hash(message)
    hashed_message_base64 = b64.b64encode(message_hash).decode()

    data_to_check = {'message': hashed_message_base64, 'timestamp': timestamp}
    data_json = json.dumps(data_to_check).encode()

    try:
        signature_bytes = b64.b64decode(signature.encode())
        tsa_public_key.verify(
            signature_bytes,
            data_json,
            padding.PSS(
                mgf=padding.MGF1(hashes.SHA256()),
                salt_length=padding.PSS.MAX_LENGTH
                ),
            hashes.SHA256()
        )
        return True
    except Exception as e:
        print("Error checking the TSA signature: ", e)
        return False

    

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Client")
    parser.add_argument("-user", help="User PKCS12 file")
    args = parser.parse_args()
    user_keystore = args.user
    run_client()
