import socket
import json
import socket_functions
import crypto_lib
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

    def get_bank_accounts(self):
        with open("bank_accounts.json", "r") as balances:
            return_list = json.load(balances)
        return return_list

    def client_has_enough_balance(self, sum):
        if self.bank_accounts[0][1] - sum >= 0:
            return True
        else:
            return False

    def perform_transaction(self, sum):
        self.bank_accounts[0][1] -= sum
        self.bank_accounts[1][1] += sum
        with open("bank_accounts.json", "w") as balances:
            json.dump(self.bank_accounts, balances)

    def show_balance(self):
        print("Client balance is: " + str(self.bank_accounts[0][1]))
        print("Merchant balance is: " + str(self.bank_accounts[1][1]))


def recv_message_4(merchant_conn):
    message = socket_functions.socket_recv(merchant_conn)
    message, AES_key_PG_M, AES_IV_PG_M = socket_functions.split_message(message)
    AES_key_PG_M = crypto_lib.decrypt_RSA(AES_key_PG_M, private_key_rsa)
    AES_IV_PG_M = crypto_lib.decrypt_RSA(AES_IV_PG_M, private_key_rsa)
    message = crypto_lib.decrypt_AES(message, AES_key_PG_M, AES_IV_PG_M)
    PM, sigM, AES_key_PG_C, AES_IV_PG_C = socket_functions.split_message(message)
    AES_key_PG_C = crypto_lib.decrypt_RSA(AES_key_PG_C, private_key_rsa)
    AES_IV_PG_C = crypto_lib.decrypt_RSA(AES_IV_PG_C, private_key_rsa)
    PM = crypto_lib.decrypt_AES(PM, AES_key_PG_C, AES_IV_PG_C)
    print(PM)
    print(sigM)


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
