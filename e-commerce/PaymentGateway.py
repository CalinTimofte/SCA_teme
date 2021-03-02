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

with open("Keys/merchant_rsa_pub_key.txt", "rb") as key_file:
    public_key_rsa_merchant = serialization.load_pem_public_key(
        key_file.read()
    )

with open("Keys/client_rsa_pub_key.txt", "rb") as key_file:
    public_key_rsa_client = serialization.load_pem_public_key(
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


def check_card_details(CardN, CardExp, CCode):
    if (CardN.decode() == "123456789101" and CardExp.decode() == "11/22" and CCode.decode() == "123"):
        return True
    else:
        return False


def check_if_Nonce_sid_combo_fresh(Nonce, SID):
    return True


def check_if_client_cert_fresh(cert):
    return True


def recv_message_4(merchant_conn):
    print("Received 4th message")
    message = socket_functions.socket_recv(merchant_conn)
    message, AES_key_PG_M, AES_IV_PG_M = socket_functions.split_message(message)
    AES_key_PG_M = crypto_lib.decrypt_RSA(AES_key_PG_M, private_key_rsa)
    AES_IV_PG_M = crypto_lib.decrypt_RSA(AES_IV_PG_M, private_key_rsa)
    message = crypto_lib.decrypt_AES(message, AES_key_PG_M, AES_IV_PG_M)
    PM, sigM, AES_key_PG_C, AES_IV_PG_C = socket_functions.split_message(message)
    AES_key_PG_C = crypto_lib.decrypt_RSA(AES_key_PG_C, private_key_rsa)
    AES_IV_PG_C = crypto_lib.decrypt_RSA(AES_IV_PG_C, private_key_rsa)
    PM = crypto_lib.decrypt_AES(PM, AES_key_PG_C, AES_IV_PG_C)
    CardN, CardExp, CCode, sid, amount, PubKC, NC, M, sigC = socket_functions.split_message(PM)

    # Check merchant signature
    merchant_sig_msg = socket_functions.concat_messages(sid, PubKC, amount)
    if crypto_lib.verify_signature_is_valid(sigM, merchant_sig_msg, public_key_rsa_merchant):
        print("The signature is from the merchant")
    else:
        print("The signature is invalid")
        resp = b"Denied"
        return resp, sid, amount, NC, AES_key_PG_M, AES_IV_PG_M

    # Check client signature
    client_sig_msg = socket_functions.concat_messages(CardN, CardExp, CCode, sid, amount, PubKC, NC, M)
    if crypto_lib.verify_signature_is_valid(sigC, client_sig_msg, public_key_rsa_client):
        print("The signature is from the client ")
    else:
        print("The signature is invalid")
        resp = b"Denied"
        return resp, sid, amount, NC, AES_key_PG_M, AES_IV_PG_M

    if check_card_details(CardN, CardExp, CCode):
        print("The card details are correct")
    else:
        print("Card details invalid")
        resp = b"Denied, bad card details"
        return resp, sid, amount, NC, AES_key_PG_M, AES_IV_PG_M

    if not check_if_Nonce_sid_combo_fresh(NC, sid):
        resp = b"Denied, replay attack"
        return resp, sid, amount, NC, AES_key_PG_M, AES_IV_PG_M

    if not check_if_client_cert_fresh(PubKC):
        resp = b"Denied, replay attack"
        return resp, sid, amount, NC, AES_key_PG_M, AES_IV_PG_M

    transaction_mock = TransactionSim()
    if transaction_mock.client_has_enough_balance(int(amount.decode())):
        print("Before transaction:")
        transaction_mock.show_balance()
        transaction_mock.perform_transaction(int(amount.decode()))
        print("After transaction:")
        transaction_mock.show_balance()
        resp = b"Accepted, transaction performed"
        return resp, sid, amount, NC, AES_key_PG_M, AES_IV_PG_M
    else:
        resp = b"Denied, client doesn't have enough balance"
        return resp, sid, amount, NC, AES_key_PG_M, AES_IV_PG_M


def send_message_5(merchant_conn, resp, sid, amount, NC, AES_key_PG_M, AES_IV_PG_M):
    print("Sent 5th message.")
    message_to_sign = socket_functions.concat_messages(resp, sid, amount, NC)
    signature = crypto_lib.sign(message_to_sign, private_key_rsa)
    message_to_send = socket_functions.concat_messages(resp, sid, signature)
    message_to_send = crypto_lib.encrypt_AES(message_to_send, AES_key_PG_M, AES_IV_PG_M)
    socket_functions.socket_send(merchant_conn, message_to_send)


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
    resp, sid, amount, NC, AES_key_PG_M, AES_IV_PG_M = recv_message_4(merchant_conn)
    send_message_5(merchant_conn, resp, sid, amount, NC, AES_key_PG_M, AES_IV_PG_M)

    merchant_conn.close()  # close the connection


if __name__ == '__main__':
    server_program()
