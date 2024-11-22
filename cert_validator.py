from datetime import datetime, timedelta, timezone

from cryptography import x509
from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric.padding import PKCS1v15
from cryptography.x509 import Certificate
from cryptography.x509.extensions import BasicConstraints, KeyUsage


class CertificateValidator:
    "A class for validating X.509 certificates."

    def __init__(self):

        self.ca_cert: Certificate = "certs/MSG_CA.crt"
        try:
            with open(self.ca_cert, "rb") as cert_file:
                certificate_data = cert_file.read()
            self.ca_cert = x509.load_pem_x509_certificate(certificate_data)
        except (ValueError, FileNotFoundError):
            print(f"Error loading trusted certificate: {self.ca_cert}")

    "Validates an X.509 certificate."

    def validate_certificate(self, certificate: Certificate, expected_identity: str):

        if (
            self.verify_signature(certificate)
            and self.validate_validity(certificate)
            and self.verify_identity(certificate, expected_identity)
            and self.validate_critical_extensions(certificate)
        ):
            return True

        return False

    "Verifies the certificate's signature using a trusted CA certificate."

    def verify_signature(self, certificate: Certificate):

        issuer = certificate.issuer
        if issuer == self.ca_cert.subject:
            try:
                self.ca_cert.public_key().verify(
                    certificate.signature,
                    certificate.tbs_certificate_bytes,
                    PKCS1v15(),
                    hashes.SHA256(),
                )
                return True
            except InvalidSignature:
                print("Invalid signature for certificate issued by", issuer)
                return False

        return False

    "Validates the certificate's validity period."

    def validate_validity(self, certificate: Certificate):

        now = datetime.now().astimezone(timezone.utc) + timedelta(hours=1)
        if (
            now < certificate.not_valid_before_utc
            or now > certificate.not_valid_after_utc
        ):
            print("Certificate date is not valid!")
            return False
        return True

    "Verifies the certificate's subject identity against the expected identity."

    def verify_identity(self, certificate: Certificate, expected_identity):

        if (
            certificate.subject.get_attributes_for_oid(x509.NameOID.PSEUDONYM)[0].value
            != expected_identity
        ):
            print(
                f"Certificate subject does not match expected identity: {expected_identity}"
            )
            print(
                f"Actual subject: {certificate.subject.get_attributes_for_oid(x509.NameOID.PSEUDONYM)[0].value}"
            )
            return False
        return True

    "Validates the values of critical extensions."

    def validate_critical_extensions(self, certificate):

        for extension in certificate.extensions:
            if extension.critical:
                if isinstance(extension.value, BasicConstraints):
                    # Checks if the certificate is not a CA certificate
                    if extension.value.ca:
                        print("Certificate marked as CA but is not a CA certificate.")
                        return False
                elif isinstance(extension.value, KeyUsage):
                    # Checks if the certificate allows digital signatures
                    if not extension.value.digital_signature:
                        print("KeyUsage extension does not allow digital signature.")
                        return False
                else:
                    print(f"Unhandled critical extension type: {extension.value}")
                    return False
        return True
