from cryptography import x509
from cryptography.x509.oid import NameOID
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.serialization import Encoding
from cryptography.hazmat.primitives.serialization.pkcs12 import serialize_key_and_certificates
from cryptography.x509 import SubjectAlternativeName
from cryptography.x509 import DNSName
import getpass
import datetime

def prompt_for_certificate_info(cert_type):
    print(f"\n\033[1m{cert_type} Certificate Information:\033[0m")
    country = input("\033[1mCountry Name (2 letter code):\033[0m ")
    while country.isalpha() == False or len(country) != 2:
        print("\033[31mInvalid country code. Please enter a 2-letter country code.\033[0m")
        country = input("\033[1mCountry Name (2 letter code):\033[0m ")
    state = input("\033[1mState or Province Name:\033[0m ")
    locality = input("\033[1mLocality Name:\033[0m ")
    organization = input("\033[1mOrganization Name:\033[0m ")
    common_name = input("\033[1mCommon Name:\033[0m ")
    san = input("\033[1mEnter Subject Alternative Names (comma separated):\033[0m ")
    san_list = san.split(',')
    san_list = [DNSName(i.strip()) for i in san_list]
    return country, state, locality, organization, common_name, san_list

def generate_certificate(cert_type, issuer_cert, issuer_key, validity_days, key_size=2048):
    country, state, locality, organization, common_name, san_list = prompt_for_certificate_info(cert_type)
    key = rsa.generate_private_key(public_exponent=65537, key_size=key_size)
    cert_builder = x509.CertificateBuilder().subject_name(x509.Name([
        x509.NameAttribute(NameOID.COUNTRY_NAME, country),
        x509.NameAttribute(NameOID.STATE_OR_PROVINCE_NAME, state),
        x509.NameAttribute(NameOID.LOCALITY_NAME, locality),
        x509.NameAttribute(NameOID.ORGANIZATION_NAME, organization),
    ])).public_key(
        key.public_key()
    ).serial_number(
        x509.random_serial_number()
    ).not_valid_before(
        datetime.datetime.now(datetime.timezone.utc)
    ).not_valid_after(
        datetime.datetime.now(datetime.timezone.utc) + datetime.timedelta(days=validity_days)
    )
    cert_builder = cert_builder.add_extension(SubjectAlternativeName(san_list), critical=False)
    if issuer_cert is None and issuer_key is None: 
        cert = cert_builder.issuer_name(x509.Name([
            x509.NameAttribute(NameOID.COUNTRY_NAME, country),
            x509.NameAttribute(NameOID.STATE_OR_PROVINCE_NAME, state),
            x509.NameAttribute(NameOID.LOCALITY_NAME, locality),
            x509.NameAttribute(NameOID.ORGANIZATION_NAME, organization),
            x509.NameAttribute(NameOID.COMMON_NAME, common_name),
        ])).sign(key, hashes.SHA256())
    else:
        if issuer_cert != None:
            cert = cert_builder.issuer_name(issuer_cert.subject).sign(issuer_key, hashes.SHA256())
        else:
            raise ValueError("Issuer certificate is required.")
    return key, cert

def save_to_file(filename, key, cert, encoding, password=None):
    with open(filename, "wb") as f:
        if filename.endswith('.key'):
            encryption_algorithm = serialization.NoEncryption() if not password else serialization.BestAvailableEncryption(password.encode())
            f.write(key.private_bytes(
                encoding = serialization.Encoding.PEM,
                format = serialization.PrivateFormat.TraditionalOpenSSL,
                encryption_algorithm=encryption_algorithm
            ))
        elif filename.endswith('.pem') or filename.endswith('.crt'):
            f.write(cert.public_bytes(encoding))
        elif filename.endswith('.p12'):
            encryption_algorithm = serialization.NoEncryption() if not password else serialization.BestAvailableEncryption(password.encode())
            p12_data = serialize_key_and_certificates(None, key, cert, None, encryption_algorithm)
            f.write(p12_data)
        else:
            print(f"Unsupported file format for file {filename}")

def main():
    print("""
  ____          _      ____                           _             
 / ___|___ _ __| |_   / ___| ___ _ __   ___ _ __ __ _| |_ ___  _ __ 
| |   / _ \ '__| __| | |  _ / _ \ '_ \ / _ \ '__/ _` | __/ _ \| '__|
| |__|  __/ |  | |_  | |_| |  __/ | | |  __/ | | (_| | || (_) | |   
 \____\___|_|   \__|  \____|\___|_| |_|\___|_|  \__,_|\__\___/|_|   

            Generate RSA Root and Server Certificates/Keys
       
          """)
    cert_format = ""
    while cert_format not in ["pem", "p12", "crt"]:
        cert_format = input("Enter the format for the certificate (pem/p12/crt): ")
        if cert_format not in ["pem", "p12", "crt"]:
            print("Invalid format. Please enter either 'pem', 'p12', or 'crt'.")

    password = getpass.getpass("Enter the password for the key: ")
    confirm_password = getpass.getpass("Confirm the password: ")
    while password != confirm_password:
        print("Passwords do not match. Please try again.")
        password = getpass.getpass("Enter the password for the certificate: ")
        confirm_password = getpass.getpass("Confirm the password: ")

    validity_days = int(input("Enter the validity period in days for the certificates: "))
    root_key, root_cert = generate_certificate("Root", issuer_cert=None, issuer_key=None, validity_days=validity_days)
    server_key, server_cert = generate_certificate("Server", root_cert, root_key, validity_days)
    save_to_file(f"root_key.key", root_key, root_cert, serialization.Encoding.PEM, password)
    save_to_file(f"root_cert.{cert_format}", root_key, root_cert, serialization.Encoding.PEM, password)
    save_to_file(f"server_key.key", server_key, server_cert, serialization.Encoding.PEM, password)
    save_to_file(f"server_cert.{cert_format}", server_key, server_cert, serialization.Encoding.PEM, password)
    
if __name__ == "__main__":
    main()