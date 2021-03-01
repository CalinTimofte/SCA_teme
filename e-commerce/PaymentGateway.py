import socket
import json
from cryptography.hazmat.primitives import serialization

# RSA keys
with open("Keys/pg_rsa_priv_key.txt", "rb") as key_file:
    private_key_rsa = serialization.load_pem_private_key(
        key_file.read(),
        password=None,
    )

with open("Keys/pg_rsa_pub_key.txt", "rb") as key_file:
    public_key_rsa = serialization.load_pem_public_key(
        key_file.read()
    )

class TransactionSim:
    def __init__(self):
        self.bank_accounts = self.get_bank_accounts()
        print(self.bank_accounts)

    def get_bank_accounts(self):
        with open("bank_accounts.json", "r") as updater:
            return_obj = json.load(updater)
        return return_obj

    def update_bank_accounts(self):
        pass

Trans_sim = TransactionSim()


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

# if __name__ == '__main__':
#     server_program()
