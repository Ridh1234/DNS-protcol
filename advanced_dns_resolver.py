import socket
import struct
import random
import dns.resolver
import ipaddress
import whois
import ssl
import certifi
import socket
from typing import Dict, List, Any

class AdvancedDNSResolver:
    def __init__(self, dns_server='8.8.8.8'):
        self.dns_server = dns_server
        self.resolver = dns.resolver.Resolver(configure=False)
        self.resolver.nameservers = [dns_server]

    def resolve_dns(self, domain: str) -> Dict[str, Any]:
        """Comprehensive DNS resolution"""
        result = {
            'domain': domain,
            'ipv4': [],
            'ipv6': [],
            'mx_records': [],
            'txt_records': [],
            'ns_records': []
        }

        try:
            # IPv4 Records
            ipv4_answers = dns.resolver.resolve(domain, 'A')
            result['ipv4'] = [str(rdata) for rdata in ipv4_answers]

            # IPv6 Records
            try:
                ipv6_answers = dns.resolver.resolve(domain, 'AAAA')
                result['ipv6'] = [str(rdata) for rdata in ipv6_answers]
            except dns.resolver.NoAnswer:
                result['ipv6'] = []

            # MX Records
            mx_answers = dns.resolver.resolve(domain, 'MX')
            result['mx_records'] = [str(rdata.exchange) for rdata in mx_answers]

            # TXT Records
            txt_answers = dns.resolver.resolve(domain, 'TXT')
            result['txt_records'] = [rdata.strings[0].decode() for rdata in txt_answers]

            # Name Server Records
            ns_answers = dns.resolver.resolve(domain, 'NS')
            result['ns_records'] = [str(rdata) for rdata in ns_answers]

        except Exception as e:
            result['error'] = str(e)

        return result

    def get_whois_info(self, domain: str) -> Dict[str, Any]:
        """Retrieve WHOIS information"""
        try:
            w = whois.whois(domain)
            return {
                'registrar': w.registrar,
                'creation_date': str(w.creation_date),
                'expiration_date': str(w.expiration_date),
                'name_servers': w.name_servers
            }
        except Exception as e:
            return {'error': str(e)}

    def check_ssl(self, domain: str) -> Dict[str, Any]:
        """Check SSL certificate details"""
        try:
            context = ssl.create_default_context(cafile=certifi.where())
            with socket.create_connection((domain, 443)) as sock:
                with context.wrap_socket(sock, server_hostname=domain) as secure_sock:
                    cert = secure_sock.getpeercert()
                    return {
                        'issuer': dict(x[0] for x in cert['issuer']),
                        'subject': dict(x[0] for x in cert['subject']),
                        'version': cert['version'],
                        'expiration': cert['notAfter']
                    }
        except Exception as e:
            return {'error': str(e)}

    def network_info(self, ip: str) -> Dict[str, Any]:
        """Get additional network information for an IP"""
        try:
            ip_obj = ipaddress.ip_address(ip)
            return {
                'ip': str(ip_obj),
                'version': ip_obj.version,
                'is_private': ip_obj.is_private,
                'is_global': ip_obj.is_global,
                'network_info': str(ipaddress.ip_network(ip + '/24', strict=False))
            }
        except Exception as e:
            return {'error': str(e)}

# Example usage
if __name__ == "__main__":
    resolver = AdvancedDNSResolver()
    domain = 'google.com'
    
    print("DNS Resolution:", resolver.resolve_dns(domain))
    print("\nWHOIS Info:", resolver.get_whois_info(domain))
    
    try:
        ip = resolver.resolve_dns(domain)['ipv4'][0]
        print("\nNetwork Info:", resolver.network_info(ip))
        print("\nSSL Info:", resolver.check_ssl(domain))
    except Exception as e:
        print("Error:", e)