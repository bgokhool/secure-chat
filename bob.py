"""
This is the second client of a peer-to-peer two person chat application
used to demonstrate different crypto-systems.

Comments:
I have have not made this too general and simplified
(i.e. hard-coded) certain stuff like names of
my contact and kept the number of allowed contacts to one (always Alice)
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
import primes

class Client_B():
    ALICE = "Alice"
    BOB = "Bob"
    COMMON_PW = "Password"

    client_names = {}
    addresses = {}

    HOST = ''
    PORT = 12351
    BUFSIZ = 1024
    addr = bob_socket = None
    stop_threads = False

    def __init__(self, n):
        self.n = n
        self.p = primes.PRIMES[str(n)][0]
        self.g = primes.PRIMES[str(n)][1]
        print("Trying to connect to %s..."% self.ALICE)
        addr = (self.HOST, self.PORT)
        self.bob_socket = socket(AF_INET, SOCK_STREAM)
        self.bob_socket.connect(addr)
        print("Successfully connected to %s"% self.ALICE)

        # turn pw into a number mod
        pw_num = 0
        for c in self.COMMON_PW:
            pw_num = (pw_num + ord(c)) % self.p

        # start up key exchange
        bob_spake = spake.SPAKE(pw_num, self.p, self.g)
        bob_spake_y = bob_spake.get_x_star()
        print("Bob's Y*", bob_spake_y)
        self.bob_socket.send(bytes(str(bob_spake_y), "utf-8"))
        msg = self.bob_socket.recv(self.BUFSIZ)
        stringmsg = msg.decode('utf-8')
        alice_spake_x = int(stringmsg)
        print("Alice's X*", alice_spake_x)
        bob_spake.complete_exchange(alice_spake_x)

        print(bob_spake.get_hex_key())

        ACCEPT_THREAD = Thread(target=self.handle)
        ACCEPT_THREAD.start()
        ACCEPT_THREAD.join()
        self.bob_socket.close()


    def display(self, name, msg):
        """Displays a client's message"""
        msg_to_display = name + ": " + msg
        print(msg_to_display)

    def receive_message(self):
        """Receives all messages from Alice."""

        name = self.ALICE
        while True and not self.stop_threads:
            try:
                msg = self.bob_socket.recv(self.BUFSIZ)
                stringmsg = msg.decode('utf-8')
                if msg == bytes("{quit}", "utf-8"):
                    self.bob_socket.send(bytes("{quit}", "utf-8"))
                    self.bob_socket.close()
                    info_msg = "%s has left the chat." % name
                    self.display(name, info_msg)
                    self.stop_threads = True
                    break
                self.display(name, stringmsg)
            except OSError:  # Possibly client has left the chat.
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

    def handle(self):
        """
        Gets a client's name and initiates an
        asynchronous chat with them
        """
        # self.get_client_name(client)
        CLIENT_RCV_MSG = Thread(target=self.receive_message)
        CLIENT_RCV_MSG.start()
        self.send_msg()

    def send_msg(self):
        """Continuously send messages to client"""
        while True and not self.stop_threads:
            msg = input()
            if msg == "{quit}":
                # self.bob_socket.close()
                self.bob_socket.send(bytes(msg, "utf-8"))
                self.stop_threads = True
                return
            else:
                self.bob_socket.send(bytes(msg, "utf-8"))


if __name__ == "__main__":
    Client_B(1024)
