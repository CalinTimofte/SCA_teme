import socket


def recv_message_4(merchant_conn):
    pass


def send_message_5(merchant_conn):
    pass


def server_program():
    # get the hostname
    host = socket.gethostname()
    port = 5001  # initiate port no above 1024

    server_socket = socket.socket()  # get instance
    # look closely. The bind() function takes tuple as argument
    server_socket.bind((host, port))  # bind host address and port together

    # configure how many client the server can listen simultaneously
    server_socket.listen(2)
    merchant_conn, merchant_address = server_socket.accept()  # accept new connection
    print("Connection from: " + str(merchant_address))

    # Exchange sub-protocol
    recv_message_4(merchant_conn)
    send_message_5(merchant_conn)

    merchant_conn.close()  # close the connection


if __name__ == '__main__':
    server_program()
