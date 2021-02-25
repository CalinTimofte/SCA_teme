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

    merchant_socket = socket.socket()  # instantiate
    merchant_socket.connect((host, port))  # connect to the server

    # Setup sub-protocol
    send_message_1(merchant_socket)
    recv_message_2(merchant_socket)

    # Exchange sub-protocol
    send_message_3(merchant_socket)
    recv_message_6(merchant_socket)

    merchant_socket.close()  # close the connection


if __name__ == '__main__':
    client_program()
