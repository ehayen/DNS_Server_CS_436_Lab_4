import errno
import socket
import sys
import threading
import time
from tabulate import tabulate


def listen():
    try:
        while True:
            # Wait for query

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
            pass
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

    listen()
    recordTable = RRTable()
    recordTable.display_table()


def serialize():
    # Consider creating a serialize function
    # This can help prepare data to send through the socket
    pass


def deserialize():
    # Consider creating a deserialize function
    # This can help prepare data that is received from the socket
    pass


class RRTable:
    def __init__(self):
        self.record_number = 0
        self.records = {}
        initialRecords = [
            ["www.csusm.edu", "A", "144.37.5.45", "NONE", 1],
            ["my.csusm.edu", "A", "144.37.5.150", "NONE", 1],
            ["amazone.com", "NS", "dns.amazone.com", "NONE", 1],
            ["dns.amazone.com", "A", "127.0.0.1", "NONE", 1]
        ]



        # Start the background thread
        self.lock = threading.Lock()
        self.thread = threading.Thread(target=self.__decrement_ttl, daemon=True)
        self.thread.start()

        for record in initialRecords:
            self.add_record(record)

    def add_record(self, record):
        with self.lock:
            self.record_number += 1
            self.records[record[0]] = {
                "number": self.record_number,
                "type": record[1],
                "result": record[2],
                "ttl": record[3],
                "static": record[4],
            }

    def get_record(self, name):
        with self.lock:
            return self.records[name][2]

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
                removeRecordsList = []
                for name in self.records:
                    if self.records[name][3] == 0:
                        self.records[name][2] -=1
                        if self.records[name][2] == 0:
                            removeRecordsList.append(name)
                for name in removeRecordsList:
                    self.__remove_expired_records(name)
            time.sleep(1)

    def __remove_expired_records(self, name):
        # This method is only called within a locked context
        self.records.pop(name)

        # Remove expired records
        # Update record numbers
        pass


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
