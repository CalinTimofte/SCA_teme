import socket


def send_message_1(client_socket):
    pass


def recv_message_2(client_socket):
    pass


def send_message_3(client_socket):
    pass


def recv_message_6(client_socket):
    pass


def client_program():
    host = socket.gethostname()  # as both code is running on same pc
    port = 5000  # socket server port number

    client_socket = socket.socket()  # instantiate
    client_socket.connect((host, port))  # connect to the server

    # Setup sub-protocol
    send_message_1(client_socket)
    recv_message_2(client_socket)

    # Exchange sub-protocol
    send_message_3(client_socket)
    recv_message_6(client_socket)

    client_socket.close()  # close the connection


if __name__ == '__main__':
    client_program()
