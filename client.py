# import socket module
from http import server
from socket import *
import sys  # In order to terminate the program
import threading  # for multithreading

serverName = ''
serverPort = 6789

record_table = []


def handle_client(connectionSocket):
    try:
        message = connectionSocket.recv(1024).decode()


        filename = message.split()[1][1:]
        if filename.lower().startswith("grades"):
            connectionSocket.send("HTTP/1.1 403 Forbidden\r\n\r\n".encode())
            return
        # Open requested file
        f = open(filename)
        # Read file data
        outputdata = f.read()
        # Send HTTP OK status
        connectionSocket.send("HTTP/1.1 200 OK\r\n\r\n".encode())
        # Send the content of the requested file to the client
        for i in range(0, len(outputdata)):
            connectionSocket.send(outputdata[i].encode())
            connectionSocket.send("\r\n".encode())
    except IOError:
        # Send response message for file not found
        connectionSocket.send("HTTP/1.1 404 Not Found\r\n\r\n".encode())
    finally:
        # Close client socket
        connectionSocket.close()
        # Close server socket


serverSocket = socket(AF_INET, SOCK_STREAM)
# Prepare a server socket on a particular port
serverSocket.bind((serverName, serverPort))
serverSocket.listen(1)
while True:
    # Establish the connection
    print("Ready to serve...")
    connectionSocket, addr = serverSocket.accept()
    threading.Thread(target=handle_client, args=(connectionSocket,)).start()
    serverSocket.close()
    # Terminate the program after sending the corresponding data
    sys.exit()
