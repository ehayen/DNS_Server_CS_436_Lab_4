import errno
import socket
import sys
import threading
import time
import struct
import random
from tabulate import tabulate
def handle_request(hostname: str, query_code: int, records: "RRTable", num: int, connection):
    # Check RR table for record
    if(records.get_record(hostname) == None):
        # If not found, ask the local DNS server, then save the record if valid
        local_dns_address = (get_local_ip(), 21000)

        
        message = { 
            "trans_id":random.getrandbits(32), #Unique randomly generated 32 bit transaction id
            "flag": "QUERY",
            "name": hostname,
            "type": DNSTypes.get_type_name(query_code)
        }
        #print(message["trans_id"])
        # test prints
        #print(dataq)
        #print(serialize(dataq))


        connection.send_message(message, local_dns_address)
        response, address = connection.receive_message()


        record_back = {
            "name": response["name"],
            "type": response["type"],
            "result": response["result"],
            "ttl": response["ttl"],
            "static" : 0
        }
        records.add_record(record_back)
    # The format of the DNS query and response is in the project description

    # Display RR table
    records.display_table()


def main():
    records = RRTable()
    num = 0
    client_address = (get_local_ip(), 4096)

    try:

        connection = UDPConnection()
        connection.bind(client_address)

        while True:
            input_value = input("Enter the hostname (or type 'quit' to exit) ")
            if input_value.lower() == "quit":
                break

            hostname = input_value
            query_code = DNSTypes.get_type_code("A")

            # For extra credit, let users decide the query type (e.g. A, AAAA, NS, CNAME)
            # This means input_value will be two values separated by a space

            handle_request(hostname,query_code,records, num, connection)

    except KeyboardInterrupt:
        print("Keyboard interrupt received, exiting...")
    finally:
        connection.close()
        pass

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

class RRTable:
    def __init__(self):
        self.record_number = 0
        self.records = {}

        # Start the background thread
        self.lock = threading.Lock()
        self.thread = threading.Thread(target=self.__decrement_ttl, daemon=True)
        self.thread.start()

    def add_record(self, record):
        """
        record = {
            name : the host name queried
            type : the record type being requested
            ttl : the TTL of the data
            result : the requested data
        """
        with self.lock:
            self.record_number += 1
            record["record_number"] = self.record_number
            self.records[record["name"]] = record

    def get_record(self, name):
        with self.lock:
            if name in self.records:
                return self.records[name]
            else:
                return None

    def display_table(self):
        with self.lock:
            # Display the table in the following format (include the column names):
            # record_number,name,type,result,ttl,static
            headers = ["","NAME", "TYPE", "RESULT", "TTL", "STATIC"]
            table = []
            for name in self.records:
                record = self.records[name]
                row = record["record_number"], name, record["type"], record["result"], record["ttl"], record["static"]
                table.append(row)
            print("\n")
            print(tabulate(table, headers=headers, tablefmt="plain"))
            print("\n")



    def __decrement_ttl(self):
        while True:
            with self.lock:
                # Decrement ttl
                remove_records_list = []
                for record in self.records.values():
                    if record["static"] == 0:
                        record["ttl"] -=1
                        if record["ttl"] < 1:
                            remove_records_list.append(record["name"])
                for name in remove_records_list:
                    self.__remove_expired_records(name)
            time.sleep(1)

    def __remove_expired_records(self, name):
        # This method is only called within a locked context
        num = self.records[name]["record_number"]
        self.records.pop(name)
        for record in self.records.values():
            if record["record_number"] > num:
                record["record_number"]-=1

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

    def send_message(self, message, address: tuple[str, int]):
        """Sends a message to the specified address."""
        self.socket.sendto(serialize(message), address)

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
                return deserialize(data), address
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
