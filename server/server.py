# encoding: utf-8
#
# jpbarraca@ua.pt
# jmr@ua.pt 2016
#
# Diogo Daniel Soares Ferreira N 76504
# Luis Davide Jesus Leira N 76514
# Segurity Messaging Repository System 2017-2018



from socket import *
from select import *
import json
import sys
import time
import logging
import getpass
from log import *
from server_client import *
from server_registry import *
from server_actions import *
from cryptography.exceptions import *

# Server address
HOST = ""   # All available interfaces
PORT = 8080  # The server port

# Maximum buffer size for one packet
BUFSIZE = 512 * 1024


class Server:

	def __init__(self, host, port, privKey):
		self.ss = socket(AF_INET, SOCK_STREAM)  # the server socket (IP \ TCP)
		self.ss.setsockopt(SOL_SOCKET, SO_REUSEADDR, 1)
		self.ss.bind((host, port))
		self.ss.listen(10)
		log(logging.INFO, "Secure IM server listening on %s" %
			str(self.ss.getsockname()))

		self.registry = ServerRegistry()
		self.server_actions = ServerActions(privKey)

		# clients to manage (indexed by socket and by name):
		self.clients = {}       # clients (key is socket)

	def stop(self):
		""" Stops the server closing all sockets
		"""
		log(logging.INFO, "Stopping Server")
		try:
			self.ss.close()
		except:
			logging.exception("Server.stop")

		for csock in self.clients:
			try:
				self.clients[csock].close()  # Client.close!
			except:
				# this should not happen since close is protected...
				logging.exception("clients[csock].close")

		# If we delClient instead, the following would be unnecessary...
		self.clients.clear()

	def addClient(self, csock, addr):
		"""Add a client connecting in csock."""
		if csock in self.clients:
			log(logging.ERROR, "Client NOT Added: %s already exists" %
				self.clients[csock])
			return

		client = Client(csock, addr)
		self.clients[client.socket] = client
		log(logging.DEBUG, "Client added: %s" % client)

	def delClient(self, csock):
		"""Delete a client connected in csock."""
		if csock not in self.clients:
			log(logging.ERROR, "Client NOT deleted: %s not found" %
				self.clients[csock])
			return

		client = self.clients[csock]

		del self.clients[client.socket]
		client.close()
		log(logging.DEBUG, "Client deleted: %s" % client)

	def accept(self):
		"""Accept a new connection.
		"""
		try:
			csock, addr = self.ss.accept()
			self.addClient(csock, addr)
		except:
			logging.exception("Could not accept client")

	def flushin(self, s):
		"""Read a chunk of data from this client.
		Enqueue any complete requests.
		Leave incomplete requests in buffer.
		This is called whenever data is available from client socket.
		"""
		client = self.clients[s]
		data = None
		try:
			data = s.recv(BUFSIZE)
			log(logging.DEBUG,
				"Received data from %s. Message:\n%r" % (client, data))
		except:
			logging.exception("flushin: recv(%s)" % client)
			self.delClient(s)
		else:
			if len(data) > 0:
				reqs, client.sessionKey = client.parseReqs(data.decode('utf-8'), client.sessionKey, client.salt)
				for req in reqs:
					self.server_actions.handleRequest(s, req, self.clients[s])
			else:
				self.delClient(s)

	def flushout(self, s):
		"""Write a chunk of data to client.
		This is called whenever client socket is ready to transmit data."""
		if s not in self.clients:
			return

		client = self.clients[s]
		try:
			sent = client.socket.send(bytes(client.bufout[:BUFSIZE], "utf-8"))
			log(logging.DEBUG, "Sent %d bytes to %s. Message:\n%r" %
				(sent, client, client.bufout[:sent]))
			# leave remaining to be sent later
			client.bufout = client.bufout[sent:]
		except:
			logging.exception("flushout: send(%s)", client)
			# logging.error("Cannot write to client %s. Closing", client)
			self.delClient(client.socket)

	def loop(self):
		while True:

			# sockets to select for reading: (the server socket + every open
			# client connection)
			rlist = [self.ss] + list(self.clients.keys())

			# sockets to select for writing: (those that have something in
			# bufout)
			wlist = [sock for sock in self.clients if len(
				self.clients[sock].bufout) > 0]

			(rl, wl, xl) = select(rlist, wlist, rlist, 0)

			# Deal with incoming data:
			for s in rl:
				if s is self.ss:
					self.accept()
				elif s in self.clients:
					self.flushin(s)
				else:
					log(logging.ERROR,
						"Incoming, but %s not in clients anymore" % s)

			# Deal with outgoing data:
			for s in wl:
				if s in self.clients:
					self.flushout(s)
				else:
					log(logging.ERROR,
						"Outgoing, but %s not in clients anymore" % s)

			for s in xl:
				log(logging.ERROR, "EXCEPTION in %s. Closing" % s)
				self.delClient(s)


def registerServer(password):
	description = {}
	derivedPassword, iv = deriveKey(stringToBytes(password))
	description["password"] = bytesToString(base64.b64encode(iv+derivedPassword))

	# Create a folder with description of server
	descDir = "description"
	if not os.path.exists(descDir):
		os.mkdir(descDir)

	with open(descDir+"/"+"description", "w") as file:
		json.dump(description, file)

	print("Place the server certificate on server/keystore/serverCertificate.crt")
	print("Place the CA certificate of the server on server/keystore/ServerCA.crt")
	print("Place the private key of the server on server/keystore/ServerKey.pem")
	print()
	print("The private key will be ciphered with the password")
	print("After the private key is ciphered, the plain text private key should be deleted for security reasons")
	input("Press enter to continue...")

	privKey = loadPrivateKeyFromFile("keystore/ServerKey.pem")
	saveKeyOnFile(serializePrivateKey(privKey, stringToBytes(password)), "keystore/ServerKeyCiphered.pem")
	
	print()
	print("The private key was ciphered. You should delete the plain text private key")
	input("Press enter to continue...")

	return True

def serverIsRegistered():
	return os.path.exists("description/description")

def checkIfPasswordMatches(password):
	path = "description/description"
	assert os.path.exists(path)

	# Get the description of the server to get the information
	with open(path, "r") as file:
		content = file.read()

	# Verify if the password match with the hash
	description = json.loads(content)
	ciphered_password = description["password"]
	parsedPassword = base64.b64decode(stringToBytes(ciphered_password))

	try:
		verifyDerivedKey(stringToBytes(password), parsedPassword[16:], parsedPassword[:16])
	except InvalidKey as e:
		print(e)
		return False

	return True

def startMenu():
	password = None
	if serverIsRegistered():
		while (True):
			password = getpass.getpass("Server password: ")
			if checkIfPasswordMatches(password):
				return password
			print("Password does not match")
	else:
		password = getpass.getpass("Create a new password for the server: ")
		registerServer(password)

	return password


if __name__ == "__main__":
	if len(sys.argv) > 1:
		PORT = int(sys.argv[1])

	logging.basicConfig(stream=sys.stdout, level=logging.DEBUG, format='%(asctime)s - %(levelname)s - %(message)s')

	serv = None
	while True:
		try:
			log(logging.INFO, "Starting Secure IM Server v1.0")
			password = startMenu()
			serv = Server(HOST, PORT, getServerPrivateKey(password))
			serv.loop()
		except KeyboardInterrupt:
			serv.stop()
			try:
				log(logging.INFO, "Press CTRL-C again within 2 sec to quit")
				time.sleep(2)
			except KeyboardInterrupt:
				log(logging.INFO, "CTRL-C pressed twice: Quitting!")
				break
		except:
			logging.exception("Server ERROR")
			if serv is not (None):
				serv.stop()
			time.sleep(10)
