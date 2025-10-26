import errno
import socket
import sys
import threading
import time
from tabulate import tabulate
import struct


def listen(connection):
    try:
        while True:
            # Wait for query
            message = connection.receive_message()

            if message:
                pass
                # deserialize
                # lookup in table
                # if not in table
                    # query authoritative dns
                    # listen for response
                    # deserialize message
                    # add to table
                # prepare response
                # serialize
                # send to client

            else:
                pass

            # Check RR table for record

            # If not found, ask the authoritative DNS server of the requested hostname/domain

            # This means parsing the query to get the domain (e.g. amazone.com from shop.amazone.com)
            # With the domain, you can do a self lookup to get the NS record of the domain (e.g. dns.amazone.com)
            # With the server name, you can do a self lookup to get the IP address (e.g. 127.0.0.1)

            # When sending a query to the authoritative DNS server, use port 22000

            # Then save the record if valid
            # Else, add "Record not found" in the DNS response

            # The format of the DNS query and response is in the project description

            # Display RR table

    except KeyboardInterrupt:
        print("Keyboard interrupt received, exiting...")
    finally:
        # Close UDP socket
        pass


def main():
    # Add initial records
    # These can be found in the test cases diagram

    local_dns_address = ("127.0.0.1", 21000)
    # Bind address to UDP socket
    connection = UDPConnection()
    connection.bind(local_dns_address)

    message = {
        "trans_id": 4856,
        "flag": "QUERY",
        "query": {"name": "yahoo", "type": "A"}
    }
    print(message)
    print(serialize(message))
    print(deserialize(serialize(message)))


    listen(connection)


def serialize(message: dict):
    """
    message has fields
    trans_id: the unique transaction id
    flag: query OR response
    query:
        name: the host name queried
        type: the record type being requested
    response:
        name: the host name queried
        type: the record type being requested
        ttl: the TTL of the data
        result: the requested data
    """
    # 32 bits for unique transaction ID
    trans_id = int(message["trans_id"])
    # 4 bits for query or response
    flag_code = 0 if message["flag"].lower() == "query" else 1
    # pack the message header
    header = struct.pack("!I", trans_id) + struct.pack("!B", flag_code)

    if flag_code == 0:
        # structure body with query
        # host name queried
        name_query = message["query"]["name"].encode() + b"\x00"
        # 4 bits for record type
        record_code = DNSTypes.get_type_code(message["query"]["type"])
        # pack the query body
        body = name_query + struct.pack("!B", record_code)

    else:
        #structure body with response
        # host name queried
        name_response = message["response"]["name"].encode() + b"\x00"
        # record type
        record_code = DNSTypes.get_type_code(message["response"]["type"])
        # time to live for record
        ttl_code = message["response"]["ttl"]
        # result of lookup
        result = message["response"]["result"].encode()
        # pack the response body
        body = name_response + struct.pack("!B", record_code) + struct.pack("!I", ttl_code) + result

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
    # unpack record type
    record_code = struct.unpack("!B", data[end_of_name+1 :end_of_name + 2])[0]
    # lookup record type
    record_type = DNSTypes.get_type_name(record_code)


    if flag_code == 0:
        # message is a query
        # add name to dictionary
        message["query"] = {}
        message["query"]["name"] = name_query
        # add record type to dictionary
        message["query"]["type"] = record_type

    else:
        # unpack ttl
        ttl_code = struct.unpack("!I", data[end_of_name + 2:end_of_name + 6])[0]
        result = data[end_of_name + 6:].decode()
        message["response"] = {}
        message["response"]["name"] = name_query
        message["response"]["type"] = record_type
        message["response"]["ttl"] = ttl_code
        message["response"]["result"] = result


    return message


class RRTable:
    def __init__(self):
        self.record_number = 0
        self.records = {}

        initialRecords = [
            ["www.csusm.edu","A", "144.37.5.45", "NONE",  1],
            ["my.csusm.edu", "A", "144.37.5.150", "NONE", 1],
            ["amazone.com", "NS", "dns.amazone.com", "NONE", 1],
            ["dns.amazone.com", "A", "127.0.0.1", "NONE", 1],
        ]

        # Start the background thread
        self.lock = threading.Lock()
        self.thread = threading.Thread(target=self.__decrement_ttl, daemon=True)
        self.thread.start()

        for record in initialRecords:
            self.add_record(record)

    def add_record(self, record):
        name, type, result, ttl, static = record
        with self.lock:
            self.record_number += 1
            self.records[name] = {
                "number": self.record_number,
                "type": type,
                "result": result,
                "ttl": ttl,
                "static": static,
            }

    def get_record(self, name):
        with self.lock:
            return self.records[name]["record"]

    def display_table(self):
        with self.lock:
            # Display the table in the following format (include the column names):
            # record_number,name,type,result,ttl,static
            headers = ["","NAME", "TYPE", "RESULT", "TTL", "STATIC"]
            table = []
            for name in self.records:
                record = self.records[name]
                row = record["number"], name, record["type"], record["result"], record["ttl"], record["static"]
                table.append(row)
            print(tabulate(table, headers=headers, tablefmt="plain"))


    def __decrement_ttl(self):
        while True:
            with self.lock:
                # Decrement ttl
                remove_records_list = []
                for name in self.records:
                    if self.records[name]["static"] == 0:
                        self.records[name]["ttl"] -=1
                        if self.records[name]["ttl"] < 1:
                            remove_records_list.append(name)
                for name in remove_records_list:
                    self.__remove_expired_records(name)
            time.sleep(1)

    def __remove_expired_records(self, name):
        # This method is only called within a locked context
        num = self.records[name]["number"]
        self.records.pop(name)
        #del self.records[name]
        for name in self.records:
            if self.records[name]["number"] > num:
                self.records[name]["number"]-=1


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


class UDPConnection:
    """A class to handle UDP socket communication, capable of acting as both a client and a server."""

    def __init__(self, timeout: int = 1):
        """Initializes the UDPConnection instance with a timeout. Defaults to 1."""
        self.socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        self.socket.settimeout(timeout)
        self.is_bound = False

    def send_message(self, message: str, address: tuple[str, int]):
        """Sends a message to the specified address."""
        self.socket.sendto(message.encode(), address)

    def receive_message(self):
        """
        Receives a message from the socket.

        Returns:
            tuple (data, address): The received message and the address it came from.

        Raises:
            KeyboardInterrupt: If the program is interrupted manually.
        """
        while True:
            try:
                data, address = self.socket.recvfrom(4096)
                return data.decode(), address
            except socket.timeout:
                continue
            except OSError as e:
                if e.errno == errno.ECONNRESET:
                    print("Error: Unable to reach the other socket. It might not be up and running.")
                else:
                    print(f"Socket error: {e}")
                self.close()
                sys.exit(1)
            except KeyboardInterrupt:
                raise

    def bind(self, address: tuple[str, int]):
        """Binds the socket to the given address. This means it will be a server."""
        if self.is_bound:
            print(f"Socket is already bound to address: {self.socket.getsockname()}")
            return
        self.socket.bind(address)
        self.is_bound = True

    def close(self):
        """Closes the UDP socket."""
        self.socket.close()


if __name__ == "__main__":
    main()
