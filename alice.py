"""
This is the first client of a peer-to-peer two person chat application
used to demonstrate different crypto-systems.

Comments:
I have have not made this too general and simplified
(i.e. hard-coded) certain stuff like names of
my contact and kept the number of allowed contacts to one (always Bob)
However, my goal being to test cryptographic schemes and key-exchange
protocols, I am not concerned with aesthetics too much.

This script could be expanded for a better chat application in the future.

@author: Bhuwan (Ashvin) Gokhool
@university: Union College
@version: Jan 2020
"""
from socket import AF_INET, socket, SOCK_STREAM
from threading import Thread
import spake


class Client_A():
    ALICE = "Alice"
    BOB = "Bob"
    COMMON_PW = "Password"

    client_names = {}
    addresses = {}

    HOST = ''
    PORT = 12345
    BUFSIZ = 1024
    addr = alice_socket = None
    stop_threads = False


    def __init__(self):
        addr = (self.HOST, self.PORT)
        self.alice_socket = socket(AF_INET, SOCK_STREAM)
        self.alice_socket.bind(addr)
        self.alice_socket.listen(5)
        print("Waiting for connection from %s..."% self.BOB)

        ACCEPT_THREAD = Thread(target=self.accept_incoming_connections)
        ACCEPT_THREAD.start()
        ACCEPT_THREAD.join()
        self.alice_socket.close()

    def accept_incoming_connections(self):
        """Sets up handling for incoming clients."""
        while True:
            if len(self.addresses) == 0:
                client, client_address = self.alice_socket.accept()
                print("%s:%s has connected." % client_address)

                # turn pw into a number mod
                pw_num = 0
                for c in self.COMMON_PW:
                    pw_num = (pw_num + ord(c)) % spake.SPAKE.p

                # start up key exchange
                alice_spake = spake.SPAKE(pw_num)
                alice_spake_x = alice_spake.get_x_star()
                print("Alice's X*", alice_spake_x)
                client.send(bytes(str(alice_spake_x), "utf-8"))
                msg = client.recv(self.BUFSIZ)
                stringmsg = msg.decode('utf-8')
                bob_spake_y = int(stringmsg)
                print("Bob's Y*", bob_spake_y)
                alice_spake.complete_exchange(bob_spake_y)

                print(alice_spake.get_hex_key())


                welcome_msg = "Hello! You have connected to %s"% self.ALICE
                client.send(bytes(welcome_msg, "utf-8"))
                self.addresses[client] = client_address
                self.client_names[client] = self.BOB
                CLIENT_HANDLE_THREAD = Thread(target=self.handle_client, args=(client,))
                CLIENT_HANDLE_THREAD.start()

    # Not really using this method, but it might be useful in a multi-party
    # chat application
    def broadcast(self, msg):
        """Broadcasts a message to all the clients."""
        for client in self.addresses:
            client.send(bytes(msg, "utf-8"))

    def display(self, name, msg):
        """Displays a client's message"""
        msg_to_display = name + ": " + msg
        print(msg_to_display)

    def receive_message(self, client):
        """
        Takes a client socket object and receives all
        messages from that client.
        """
        name = self.client_names[client]
        while True and not self.stop_threads:
            try:
                msg = client.recv(self.BUFSIZ)
                stringmsg = msg.decode('utf-8')
                if msg == bytes("{quit}", "utf-8"):
                    client.send(bytes("{quit}", "utf-8"))
                    client.close()
                    del self.addresses[client]
                    info_msg = "%s has left the chat." % name
                    self.display(name, info_msg)
                    break
                self.display(name, stringmsg)
            except OSError:  # Possibly client has left the chat.
                break
            except KeyboardInterrupt:
                break


    # We are currently not using this method because I am going to
    # hard-code the name of Bob as my recipient. This method might
    # be worthwhile exploring in the future
    def get_client_name(self, client):
        """Grabs client's name and stores it"""
        get_name = "Please type your name and press <Enter>"
        client.send(bytes(get_name, "utf-8"))
        name = client.recv(BUFSIZ).decode("utf-8")
        self.client_names[client] = name

    def handle_client(self, client):
        """
        Gets a client's name and initiates an
        asynchronous chat with them
        """
        # self.get_client_name(client)
        CLIENT_RCV_MSG = Thread(target=self.receive_message, args=(client,))
        CLIENT_RCV_MSG.start()
        self.send_msg(client)
        client.close()

    def send_msg(self, client):
        """Continuously send messages to client"""
        while True and not self.stop_threads:
            try:
                msg = input()
                if msg == "{quit}":
                    client.send(bytes(msg, "utf-8"))
                    self.stop_threads = True
                    break
                else:
                    client.send(bytes(msg, "utf-8"))
            except KeyboardInterrupt:
                break


if __name__ == "__main__":
    Client_A()
