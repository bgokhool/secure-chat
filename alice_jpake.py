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
import jpake
import datetime
import primes
import time



class Client_A():
    ALICE = "Alice"
    BOB = "Bob"
    COMMON_PW = "Password"

    client_names = {}
    addresses = {}

    HOST = ''
    PORT = 12359
    BUFSIZ = 2048
    addr = alice_socket = None
    stop_threads = False


    def __init__(self, n):
        self.n = n
        self.p = primes.PRIMES[str(n)][0]
        self.g = primes.PRIMES[str(n)][1]
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
                    pw_num = (pw_num + ord(c)) % self.p

                # start up key exchange
                start = datetime.datetime.now()
                print("Using datetime, Microseconds at Start: ", start.microsecond)

                os_start = time.process_time()

                alice_jpake = jpake.JPAKE(pw_num, "Alice", self.p, self.g)

                # Alice is storing Bob's ID which is the string "Bob"
                # when converted to number it turns out to be 275 which I hard coded
                alice_jpake.storeOtherID(275)

                alice_gx1gx2 = alice_jpake.send_first()
                # print("Alice's first msg in the exchange is:", alice_gx1gx2)
                client.send(bytes(str(alice_gx1gx2), "utf-8"))
                bob_gx3gx4_bytes = client.recv(self.BUFSIZ)
                bob_gx3gx4_str = bob_gx3gx4_bytes.decode('utf-8')
                bob_gx3gx4 = jpake.convert_first_to_tuple(bob_gx3gx4_str)
                alice_jpake.get_first(bob_gx3gx4)
                # print("Alice got Bob's first message:", bob_gx3gx4)

                alice_A = alice_jpake.send_second()
                # print("Alice's second msg in the exchange is:", alice_A)
                client.send(bytes(str(alice_A), "utf-8"))
                bob_B_bytes = client.recv(self.BUFSIZ)
                bob_B_str = bob_B_bytes.decode('utf-8')
                bob_B = jpake.convert_second_to_tuple(bob_B_str)
                alice_jpake.get_second(bob_B)
                # print("Alice got Bob's second message:", bob_B)

                alice_jpake.compute_key()
                alice_jpake.session_key()
                # print("Alice's computed session key is:", alice_jpake.get_hex_key())

                end = datetime.datetime.now()
                print("Microseconds at End: ", end.microsecond)
                time_duration = (end.second - start.second)*1000000 +\
                                end.microsecond - start.microsecond
                print("The datetime duration was: ", time_duration)

                os_end = time.process_time()
                duration = os_end - os_start # in seconds
                print("The process time in microseconds was", duration*1000000)
                # end of key exchange


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
    Client_A(960)
