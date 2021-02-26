def socket_send(socket, message):
    socket.send(message)


def socket_recv(socket):
    message = socket.recv(8192)
    return message