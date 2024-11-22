import datetime
from datetime import timezone

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives.serialization import pkcs12

import cert_validator
import utils


def generate_keystore(username: str, password: str = None):

    with open("certs/MSG_CA.key", "rb") as key_file:
        ca_rsa_private_key = serialization.load_pem_private_key(
            key_file.read(), password=None
        )

    with open("certs/MSG_CA.crt", "rb") as cert_file:
        ca_cert = x509.load_pem_x509_certificate(cert_file.read())

    # Generate a new private key for the user
    rsa_private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)

    user_cert = (
        x509.CertificateBuilder()
        .subject_name(
            x509.Name(
                [
                    x509.NameAttribute(x509.NameOID.COUNTRY_NAME, "PT"),
                    x509.NameAttribute(x509.NameOID.STATE_OR_PROVINCE_NAME, "Minho"),
                    x509.NameAttribute(x509.NameOID.LOCALITY_NAME, "Braga"),
                    x509.NameAttribute(
                        x509.NameOID.ORGANIZATION_NAME, "Universidade do Minho"
                    ),
                    x509.NameAttribute(
                        x509.NameOID.ORGANIZATIONAL_UNIT_NAME, "SSI MSG RELAY SERVICE"
                    ),
                    x509.NameAttribute(
                        x509.NameOID.COMMON_NAME, username + " (SSI MSG Relay Client)"
                    ),
                    x509.NameAttribute(x509.NameOID.PSEUDONYM, username),  # pseudonym
                ]
            )
        )
        .issuer_name(
            x509.Name(
                [
                    x509.NameAttribute(x509.NameOID.COUNTRY_NAME, "PT"),
                    x509.NameAttribute(x509.NameOID.STATE_OR_PROVINCE_NAME, "Minho"),
                    x509.NameAttribute(x509.NameOID.LOCALITY_NAME, "Braga"),
                    x509.NameAttribute(
                        x509.NameOID.ORGANIZATION_NAME, "Universidade do Minho"
                    ),
                    x509.NameAttribute(
                        x509.NameOID.ORGANIZATIONAL_UNIT_NAME, "SSI MSG RELAY SERVICE"
                    ),
                    x509.NameAttribute(
                        x509.NameOID.COMMON_NAME, "MSG RELAY SERVICE CA"
                    ),
                    x509.NameAttribute(x509.NameOID.PSEUDONYM, "MSG_CA"),
                ]
            )
        )
        .public_key(rsa_private_key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(
            datetime.datetime.now().astimezone(tz=timezone.utc)
            + datetime.timedelta(hours=1)
        )
        .not_valid_after(
            datetime.datetime.now().astimezone(tz=timezone.utc)
            + datetime.timedelta(days=100, hours=1)
        )
        .add_extension(x509.BasicConstraints(ca=False, path_length=None), critical=True)
        .add_extension(
            x509.KeyUsage(
                digital_signature=True,
                key_encipherment=False,
                content_commitment=False,
                data_encipherment=False,
                key_agreement=False,
                encipher_only=False,
                decipher_only=False,
                key_cert_sign=False,
                crl_sign=False,
            ),
            critical=True,
        )
        .add_extension(
            x509.ExtendedKeyUsage([x509.oid.ExtendedKeyUsageOID.CLIENT_AUTH]),
            critical=False,
        )
        .sign(ca_rsa_private_key, hashes.SHA256(), None)
    )

    # Save the keystore
    p12 = pkcs12.serialize_key_and_certificates(
        (username + ".p12").encode(),
        rsa_private_key,
        user_cert,
        [ca_cert],
        (
            serialization.BestAvailableEncryption(password.encode("utf-8"))
            if password
            else serialization.NoEncryption()
        ),
    )

    with open("certs/" + username + ".p12", "wb") as f:
        f.write(p12)

    return rsa_private_key, user_cert, ca_cert
