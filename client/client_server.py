#
# Diogo Daniel Soares Ferreira N 76504
# Luis Davide Jesus Leira N 76514
#
# Segurity Messaging Repository System 2017-2018

import logging
import sys
import json
from log import *
from security_actions import *

# Maximum size available in the buffer
MAX_BUFSIZE = 64 * 1024

# Terminator for the messages
TERMINATOR = "\r\n"

sys.tracebacklimit = 30

class Server:

	def __init__(self, socket, addr):
		self.socket = socket
		self.inbuffer = ""
		self.outbuffer = ""
		self.addr = addr

	def __repr__(self):
		return str(self.socket.getsockname())

	def __str__(self):
		return str(self.socket.getsockname())

	def parseMessages(self, data, sessionKey, salt):
		'''
			Parses the messages and returns complete requests in a list.
		'''
		
		# Check if the input buffer is not full
		if len(self.inbuffer) + len(data) > MAX_BUFSIZE:
			log(logging.ERROR, "Server buffer exceeds MAX BUFSIZE. %d > %d" %
					(len(bufferout) + len(data), MAX_BUFSIZE))
			self.inbuffer = ""

		self.inbuffer += data

		mess = self.inbuffer.split(TERMINATOR)
		
		# The incomplete requests stay in the input buffer
		self.inbuffer = mess[-1]

		messagesDeciphered = []

		# If exists session key, decipher the message received from client
		# With integrity check
		if sessionKey:

			for msg in mess[:-1]:
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
			
			messagesDeciphered = mess[:-1]
			# The complete requests are returned deciphered
			return messagesDeciphered, None


	def sendMessage(self, data, sessionKey=None, salt=None):
		'''
			Puts the message on the output buffer to be sent to the server
		'''

		# If exists session key, cipher the message sent to client
		# With integrity check
		try:
			if not sessionKey:
				self.outbuffer += json.dumps(data) + TERMINATOR
			else:
				key, iv, message = cipherMessageWithIntegrityCheck(stringToBytes(json.dumps(data)), sessionKey)
				self.outbuffer += bytesToString(base64.b64encode(iv + message)) + TERMINATOR
				return deriveKey(sessionKey, salt)[0]
		except:
			logging.exception("Json data could not be parsed (%s)" % data)

