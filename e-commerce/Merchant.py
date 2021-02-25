import socket


def recv_message_1(client_conn):
    pass


def send_message_2(client_conn):
    pass


def send_message_4(pg_socket):
    pass


def recv_message_5(pg_socket):
    pass


def send_message_6(client_conn):
    pass


def server_program():
    # get the hostname
    host = socket.gethostname()
    port = 5000  # initiate port no above 1024
    pg_port = 5001  # initiate port no above 1024

    server_socket = socket.socket()  # get instance
    # look closely. The bind() function takes tuple as argument
    server_socket.bind((host, port))  # bind host address and port together

    # configure how many client the server can listen simultaneously
    server_socket.listen(2)
    client_conn, client_address = server_socket.accept()  # accept new connection
    print("Connection from: " + str(client_address))

    # Setup sub-protocol
    recv_message_1(client_conn)
    send_message_2(client_conn)

    # Exchange sub-protocol
    # Open connection to PG
    pg_socket = socket.socket()  # instantiate
    pg_socket.connect((host, pg_port))  # connect to the server

    send_message_4(pg_socket)
    recv_message_5(pg_socket)
    send_message_6(client_conn)

    pg_socket.close()
    client_conn.close()  # close the connection


if __name__ == '__main__':
    server_program()
