import errno
import socket
import sys
import threading
import time

from tabulate import tabulate
import struct


def listen(connection, record_table):
    try:
        pass
        while True:
            # Wait for query
            message, received_address = connection.receive_message()

            # # testing insert
            # message = {
            #     "trans_id": 4856,
            #     "flag": "QUERY",
            #     "name": "shop.amazone.com",
            #     "type": "A"
            # }

            if message:
                # query case
                if message["flag"] == "QUERY":
                    # get record and store
                    print("Attempting to fetch record for: " + message["name"])
                    record = record_table.get_record(message["name"])

                    # test print
                    #print(record)

                    # check if record does not exist in localserver
                    if not record or not record["type"] == 'A':
                        print("Record not found. Contacting Authoritative server.", flush = True)
                        # parse message to get the NS domain
                        # split name on '.', store parts in list
                        domain_parts = message["name"].split(".")
                        # join last 2 list items around '.'
                        domain_name = ".".join(domain_parts[-2:])


                        # find authoritative server for query
                        if record_table.get_record(domain_name) == None:
                            response = {"name": message["name"], "type": "A", "result": "NXDOMAIN", "ttl": "NONE", "static": 1}
                        else:
                            authoritative_server_name = record_table.get_record(domain_name)["result"]
                            authoritative_server_address = record_table.get_record(authoritative_server_name)["result"]
                            authoritative_server_port = record_table.get_record(authoritative_server_name)["port"]
                            authoritative_address = (authoritative_server_address, authoritative_server_port)

                            # send query to authoritative server
                            connection.send_message(message, authoritative_address)
                            

                            # receive response from authoritative server
                            response = connection.receive_message()[0]

                            response["static"] = 0

                        # add response to record table
                        record_table.add_record(response)

                    # get record from table
                    record = record_table.get_record(message["name"])
                    record["trans_id"] = message["trans_id"]
                    record["flag"] = "RESPONSE"

                    record_table.display_table()

                    connection.send_message(record, received_address)

    except KeyboardInterrupt:
        print("Keyboard interrupt received, exiting...")
    finally:
        print("Closing connection...")
        connection.close()


def main():
    initial_records = [
        {"name": "www.csusm.edu", "type": "A", "result": "144.37.5.45", "ttl": "NONE", "static": 1},
        {"name": "my.csusm.edu", "type": "A", "result": "144.37.5.150", "ttl": "NONE", "static": 1},
        {"name": "amazone.com", "type": "NS", "result": "dns.amazone.com","ttl": "NONE", "static": 1},
        {"name": "dns.amazone.com", "type": "A", "result": get_local_ip(), "port": 22000, "ttl": "NONE", "static": 1},
    ]
    # initialize table to hold DNS records
    record_table = RRTable()

    # Add initial records
    for record in initial_records:
        record_table.add_record(record)

    # set address and socket for this server
    print(get_local_ip())
    local_dns_address = (get_local_ip(), 21000)
    # Bind address to UDP socket
    connection = UDPConnection()
    connection.bind(local_dns_address)

    # build testing
    query_message = {
        "trans_id": 4856,
        "flag": "QUERY",
        "name": "yahoo",
        "type": "A"
    }
    response_message = {
        "trans_id": 4857,
        "flag": "RESPONSE",
        "name": "yahoo",
        "type": "A",
        "ttl" : 60,
        "result": "125.134.1.1"
    }

###########TESTING CASES############
    #print(query_message)
    #print(serialize(query_message))
    #print(deserialize(serialize(query_message)))

    #print(response_message)
    #print(serialize(response_message))
    #print(deserialize(serialize(response_message)))
######################################

    # Start socket
    listen(connection, record_table)


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
            print(tabulate(table, headers=headers, tablefmt="plain"),flush=True)
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
