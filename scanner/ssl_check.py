import ssl
import socket
from datetime import datetime

def check_ssl_cert(hostname, port=443):
    context = ssl.create_default_context()
    try:
        with socket.create_connection((hostname, port), timeout=5) as sock:
            with context.wrap_socket(sock, server_hostname=hostname) as ssock:
                cert = ssock.getpeercert()
                not_after = datetime.strptime(cert['notAfter'], "%b %d %H:%M:%S %Y %Z")
                not_before = datetime.strptime(cert['notBefore'], "%b %d %H:%M:%S %Y %Z")
                now = datetime.utcnow()

                validity = "Valid"
                if now < not_before:
                    validity = "Certificate not yet valid"
                elif now > not_after:
                    validity = "Certificate expired"

                issuer = parse_cert_name(cert.get('issuer', []))
                subject = parse_cert_name(cert.get('subject', []))

                return {
                    "issuer": issuer,
                    "subject": subject,
                    "valid_from": cert.get('notBefore'),
                    "valid_to": cert.get('notAfter'),
                    "validity_status": validity
                }
    except ssl.SSLError as e:
        return {
            "error": "SSL Error: Certificate verify failed — hostname mismatch or self-signed.",
            "note": "The SSL certificate may be self-signed or not trusted."
        }
    except Exception as e:
        return {
            "error": f"Unexpected error: {str(e)}"
        }

def parse_cert_name(name):
    result = {}
    for rdn in name:
        for attr in rdn:
            if len(attr) >= 2:
                result[attr[0]] = attr[1]
    return result
