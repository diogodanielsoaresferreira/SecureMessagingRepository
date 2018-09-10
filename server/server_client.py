#
# Diogo Daniel Soares Ferreira N 76504
# Luis Davide Jesus Leira N 76514
#
# Segurity Messaging Repository System 2017-2018

import logging
from log import *
from security_actions import *
from server_registry import *
import json
import sys

TERMINATOR = '\r\n'
MAX_BUFSIZE = 64 * 1024

sys.tracebacklimit = 30

class Client:
	count = 0

	def __init__(self, socket, addr):
		self.socket = socket
		self.bufin = ""
		self.bufout = ""
		self.addr = addr
		self.id = None
		self.sa_data = None
		self.certificate = None
		self.pubKey = None
		self.sessionKey = None
		self.uuid = None
		self.canCommunicate=False
		self.salt = None

	def __str__(self):
		""" Converts object into string.
		"""
		return "Client(id=%r addr:%s)" % (self.id, str(self.addr))

	def asDict(self):
		return {'id': self.id}

	def parseReqs(self, data, sessionKey, salt):
		"""Parse a chunk of data from this client.
		Return any complete requests in a list.
		Leave incomplete requests in the buffer.
		This is called whenever data is available from client socket."""

		if len(self.bufin) + len(data) > MAX_BUFSIZE:
			log(logging.ERROR, "Client (%s) buffer exceeds MAX BUFSIZE. %d > %d" %
				(self, len(self.bufin) + len(data), MAX_BUFSIZE))
			self.bufin = ""

		self.bufin += str(data)

		reqs = self.bufin.split(str(TERMINATOR))
		
		self.bufin = reqs[-1]

		messagesDeciphered = []
		
		if sessionKey:
			for msg in reqs[:-1]:
				byteMessage = base64.b64decode(stringToBytes(msg))
				iv = byteMessage[0:16]
				try:
					dec_msg = decipherMessageWithIntegrityCheck(sessionKey, iv, byteMessage[16:])
					messagesDeciphered += [bytesToString(dec_msg)]
					return messagesDeciphered, deriveKey(sessionKey, salt)[0]
				except Exception as e:
				    print(e)
				    log(logging.ERROR, "Could not decipher the received message: %s" % msg)
				    return
		else:
			messagesDeciphered = reqs[:-1]
			return messagesDeciphered, None

	def sendResult(self, obj, sessionKey=None, salt=None):
		"""Send an object to this client.
		"""
		try:
			if not sessionKey:
				self.bufout += json.dumps(obj) + TERMINATOR
			else:
				key, iv, message = cipherMessageWithIntegrityCheck(stringToBytes(json.dumps(obj)), sessionKey)
				self.bufout += bytesToString(base64.b64encode(iv + message)) + TERMINATOR
				return deriveKey(sessionKey, salt)[0]
		except:
			# It should never happen! And not be reported to the client!
			logging.exception("Client.send(%s)" % self)

	def close(self):
		"""Shuts down and closes this client's socket.
		Will log error if called on a client with closed socket.
		Never fails.
		"""
		log(logging.INFO, "Client.close(%s)" % self)
		try:
			self.socket.close()
		except:
			logging.exception("Client.close(%s)" % self)

	# Loads the data from a saved client
	def loadClient(self, uuid):
		registry = ServerRegistry()
		user = registry.getUser(uuid)
		
		if user == None:
			return False
		try:
			userdata = registry.users[user]
			self.id = userdata.id
			self.certificate = loadCertificate(base64.b64decode(stringToBytes(userdata.description["Certificate"])))
			self.pubKey = loadPublicKey(base64.b64decode(stringToBytes(userdata.description["RSAPublicKey"])))
		except Exception as e:
			print(e)
			return False

		return True
