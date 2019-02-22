import struct
import time
import threading
import socket
import sys
import os

#####################################################################################################
## This is just an example file that shows the basic flaw that enabled this
## vulnerability. You can see the original go code here. on lines 75 and 38
## https://github.com/snapcore/snapd/blob/4533d900f6f02c9a04a59e49e913f04a485ae104/daemon/ucrednet.go
######################################################################################################

SERVER_ADDR = '/tmp/example.sock'
CLIENT_ADDR = '/tmp/dirty.sock;uid=0'

def parse_authentication(auth_string):
    pid = ''
    uid = ''
    socket = ''
    for token in auth_string.split(';'):
        if token.startswith('pid='):
            pid = token.split('=')[1]
        elif token.startswith('uid='):
            uid = token.split('=')[1]
        elif token.startswith('socket='):
            socket = token.split('=')[1]
    print("[SRV] Parsed Auth: pid={} uid={} socket={}".format(pid, uid, socket))

def run_server():

    # Make sure the socket doesn't already exist
    try:
        os.unlink(SERVER_ADDR)
    except OSError:
        if os.path.exists(SERVER_ADDR):
            raise

    # Create the Unix Domain Socket
    server_socket = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)

    # Bind the socket
    print("[SRV] Binding socket on {}".format(SERVER_ADDR))
    server_socket.bind(SERVER_ADDR)

    # Listen for new connections
    server_socket.listen(1)


    # Accept connection
    conn, remote_addr = server_socket.accept()
    print("[SRV] Received new connection from {}".format(remote_addr))

    # Get credentials
    credentials = conn.getsockopt(socket.SOL_SOCKET, socket.SO_PEERCRED, struct.calcsize('3i'))
    pid, uid, gid = struct.unpack('3i', credentials)
    print('[SRV] Pid={} Uid={} Gid={}'.format(pid, uid, gid))

    # Build authentication
    auth_string = ";".join(['pid=' + str(pid),
                            'uid=' + str(uid),
                            'socket=' + remote_addr])
    parse_authentication(auth_string)

    # Receive the data and echo it back
    try:
        while True:
            data = conn.recv(1024)
            if data:
                print("[SRV] Got data: {}".format(data))
                conn.sendall(data)
            else:
                break
    finally:
        print("[SRV] Closing connection to client")
        conn.close()


def run_client_random_socket():

    # Create a random Unix Domain Socket
    client_socket = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)

    # Setup socket to pass credentials in ancillary data
    client_socket.setsockopt(socket.SOL_SOCKET, socket.SO_PASSCRED, 1)

    # Connect the socket to the server socket
    try:
        print("[CLI] Connecting to server socket")
        client_socket.connect(SERVER_ADDR)
    except socket.error as err:
        print("[CLI] Error connecting: {}".format(err.message))

    try:
        # Send message to server
        msg = "ECHO"
        print("[CLI] Sending Message: {}".format(msg))
        client_socket.sendall(msg.encode('utf-8'))

        # Receive echo
        data = client_socket.recv(1024)
        print("[CLI] Received Message: {}".format(data))

    finally:
        print("[CLI] Closing socket")
        client_socket.close()

def run_client_on_named_socket():

    # Create a Unix Domain Socket
    client_socket = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)

    # Setup socket to pass credentials in ancillary data
    client_socket.setsockopt(socket.SOL_SOCKET, socket.SO_PASSCRED, 1)

    # Bind socket to named unix socket
    client_socket.bind(CLIENT_ADDR)

    # Connect the socket to the server socket
    try:
        print("[CLI] Connecting to server socket")
        client_socket.connect(SERVER_ADDR)
    except socket.error as err:
        print("[CLI] Error connecting: {}".format(err.message))

    try:
        # Send message to server
        msg = "ECHO"
        print("[CLI] Sending Message: {}".format(msg))
        client_socket.sendall(msg.encode('utf-8'))

        # Receive echo
        data = client_socket.recv(1024)
        print("[CLI] Received Message: {}".format(data))

    finally:
        print("[CLI] Closing socket")
        client_socket.close()

if __name__ == '__main__':

    # Start the server socket
    server_thread = threading.Thread(target=run_server)
    server_thread.start()

    # Sleep for a second to give the server time to start up
    time.sleep(1)

    # Run the client socket
    run_client_random_socket()

    # Wait for server socket thread to finish
    server_thread.join()

    # Clean up
    if os.path.isfile(SERVER_ADDR):
        os.unlink(SERVER_ADDR)

    if os.path.isfile(CLIENT_ADDR):
        os.unlink(CLIENT_ADDR)
