def socket_send(socket, message):
    socket.send(message)


def socket_recv(socket):
    message = socket.recv(8192)
    return message

def split_message(message):
    return message.split(b"END")

def concat_messages(*args):
    # I use the b"END" to be able to split concatenated strings on arrival
    message = args[0]
    for i in args[1:]:
        message += b"END" + i
    return message