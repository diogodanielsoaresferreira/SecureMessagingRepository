#
# Diogo Daniel Soares Ferreira N 76504
# Luis Davide Jesus Leira N 76514
#
# Segurity Messaging Repository System 2017-2018

import logging
import time
from log import *
from server_registry import *
from server_client import *
from security_actions import *
from OpenSSL import crypto
import json
import base64
from server_key_actions import *

# Maximum client response time in seconds
CLIENT_MAX_RESPONSE_TIME = 10


class ServerActions:
	def __init__(self, privateKey):

		self.messageTypes = {
			'all': self.processAll,
			'list': self.processList,
			'new': self.processNew,
			'send': self.processSend,
			'recv': self.processRecv,
			'create': self.processCreate,
			'receipt': self.processReceipt,
			'status': self.processStatus,
			'getPublicKey': self.processGetPublicKey,
			'key': self.receiveClientKey
		}

		self.registry = ServerRegistry()

		# Dictionary with the ID of the receipts to be received
		self.receipt = {}

		# Dictionary with the ID of the messages to be received
		# and its parameters
		self.messageToBeReceived = {}

		# Load server keys
		self.privateKey = privateKey
		self.publicKey = getServerPublicKey()



	def handleRequest(self, s, request, client):
		"""Handle a request from a client socket.
		"""
		try:
			logging.info("HANDLING message from %s: %r" %
						 (client, repr(request)))

			try:
				req = json.loads(request)
			except:
				logging.exception("Invalid message from client")
				return

			if not isinstance(req, dict):
				log(logging.ERROR, "Invalid message format from client")
				return


			if 'packet_id' not in req:
				log(logging.ERROR, "Client sent message without id: %s" % req)
				return

			# If the message was sent from more than 10 seconds ago,
			# Or the timestamp is from the future,
			# Discard message
			current_time = int(time.time()*1000)
			nonce = base64.b64decode(req['packet_id'])

			if 'timestamp' in req:
				if(current_time-req['timestamp']<0 or current_time-req['timestamp']>CLIENT_MAX_RESPONSE_TIME*1000):
					log(logging.ERROR, "Client sent message with wrong timestamp: %s; Current: %s" % (req['timestamp'], current_time))
					client.sendResult({"error": "wrong timestamp", "timestamp": int(time.time()*1000), "packet_id":req["packet_id"]})
					return
			else:
				log(logging.ERROR, "Client sent message without timestamp: %s" % req)
				client.sendResult({"error": "no timestamp in message", "timestamp": int(time.time()*1000), "packet_id":req["packet_id"]})
				return

			if 'type' not in req:
				log(logging.ERROR, "Message has no TYPE field")
				client.sendResult({"error": "no type field", "timestamp": int(time.time()*1000), "packet_id":req["packet_id"]})
				return

			if req['type'] in self.messageTypes:
				self.messageTypes[req['type']](req, client)
			
			elif nonce in self.messageToBeReceived:
			
				# Retrieve the message from the messages to be received
				# And remove it from the list
				message = self.messageToBeReceived[nonce]
				del self.messageToBeReceived[nonce]

				if message['type']=='key' and req['type']=='keychallenge':
					self.receiveChallenge(req, client, message["challenge"])

				if message['type']=='keychallenge' and req['type']=='SessionParameters':
					self.establishSessionKey(req, client)

			else:
				log(logging.ERROR, "Invalid message type: " +
					str(req['type']) + " Should be one of: " + str(self.messageTypes.keys()))
				client.sendResult({"error": "unknown request", "timestamp": int(time.time()*1000)})

		except Exception as e:
			logging.exception("Could not handle request")

	'''
		Certificates and key exchange
	'''
	def receiveClientKey(self, data, client):
		log(logging.DEBUG, "%s" % json.dumps(data))

		nonce = data['packet_id']

		# Generate new nonce
		newnonce = generateNonce()

		if 'certificate' not in data.keys() or 'certificatechain' not in data.keys():
			log(logging.ERROR, "Malformed message" + json.dumps(data))
			client.sendResult({"packet_id":nonce, "error": "wrong message format", "timestamp": int(time.time()*1000)})
			return

		# Get the client certificate
		try:
			certBytes = base64.b64decode(stringToBytes(data["certificate"]))
			cert = loadCertificate(certBytes)
		except Exception as e:
			print(e)
			log(logging.ERROR, "Could not load the certificate: " + json.dumps(data))
			client.sendResult({"packet_id":nonce, "error": "wrong certificate format", "timestamp": int(time.time()*1000)})
			return

		# Load client CC public key
		try:
			senderCCPublicKey = loadPubKey(dumpPublicKey(cert.get_pubkey()))
		except Exception as e:
			print(e)
			log(logging.ERROR, "Could not get the CC public key from the certificate")
			client.sendResult({"packet_id":nonce, "error": "wrong certificate format", "timestamp": int(time.time()*1000)})
			return 

		log(logging.INFO, "Client CC public key gathered")

		certificatechain =  base64.b64decode(data["certificatechain"])
		certificatechainserialized = json.loads(bytesToString(certificatechain))

		path = {}
		for certificate in certificatechainserialized:
			path[int(certificate)] = loadCertificate(certificatechainserialized[certificate])

		# Validate the certificate chain received
		valid = validateCertificateChain(cert, path)
		
		if not valid:
			log(logging.ERROR, "Certificate chain is not valid: %s " % path)
			client.sendResult({"packet_id":nonce, "error": "Could not validate the certificate chain", "timestamp": int(time.time()*1000)})
			return
		else:
			log(logging.INFO, "Client certificate chain validated")
		

		# Generate challenge to client
		challenge = os.urandom(32)
		
		# Send server certificate and signature to client
		serverCert = getServerCertificate()
		serverCertPem = dumpCertificate(serverCert)

		# Get certificate chain
		serverChain = getServerCertificatePath()
		# Serialize certificates
		serialized_path = {}
		for certificate in serverChain:
			serialized_path[str(certificate)] = bytesToString(dumpCertificate(serverChain[certificate]))

		serialized_path = stringToBytes(json.dumps(serialized_path))

		# Validate the certificate chain to be sent to server
		valid = validateCertificateChain(serverCert, serverChain)

		if not valid:
			print(e)
			log(logging.INFO, "Certificate chain could not be verified")
			client.sendResult({"packet_id":nonce, "error": "Internal server error", "timestamp": int(time.time()*1000)})
			return

		timestamp = int(time.time()*1000)
		
		client.certificate = cert

		self.messageToBeReceived[newnonce] = {
			"type": "key",
			"timestamp": timestamp,
			"challenge": challenge
		}
		
		client.sendResult({
			"packet_id": nonce,
			"new_packet_id": bytesToString(base64.b64encode(newnonce)),
			"type": "key", 
			"timestamp": timestamp,
			"result": "Client validated",
			"certificate": bytesToString(base64.b64encode(serverCertPem)),
			"certificatechain": bytesToString(base64.b64encode(serialized_path)),
			"challenge": bytesToString(base64.b64encode(challenge))
			})

	'''
		Receive the challenge from client and check response of server challenge
	'''
	def receiveChallenge(self, data, client, challenge):
		log(logging.DEBUG, "%s" % json.dumps(data))

		if 'new_packet_id' not in data.keys() or 'challenge' not in data.keys() or 'response' not in data.keys() or 'salt' not in data.keys():
			log(logging.ERROR, "Malformed message" + json.dumps(data))
			client.sendResult({"packet_id":data['new_packet_id'], "error": "wrong message format", "timestamp": int(time.time()*1000)})
			return

		nonce = data['new_packet_id']

		# Generate new nonce
		newnonce = generateNonce()

		client_response = base64.b64decode(stringToBytes(data["response"]))
		client_challenge = base64.b64decode(stringToBytes(data["challenge"]))

		# Check if response matches the challenge
		try:
			senderCCPublicKey = loadPubKey(dumpPublicKey(client.certificate.get_pubkey()))
			verifyCCSignature(senderCCPublicKey, client_response, challenge, 'sha256')
		except Exception as e:
			print(e)
			log(logging.INFO, "Response could not be verified")
			client.sendResult({"packet_id":nonce, "error": "Response could not be verified", "timestamp": int(time.time()*1000)})
			return

		# Calculate response to challenge
		try:
			response = signMessage(self.privateKey, client_challenge)
		except Exception as e:
			print(e)
			log(logging.INFO, "Signature could not be to the challenge received")
			client.sendResult({"packet_id":nonce, "error": "Internal server error", "timestamp": timestamp})
			return

		# Get the salt for session key
		try:
			decSalt = decipherAssymetricMessage(self.privateKey, base64.b64decode(stringToBytes(data["salt"])))
		except Exception as e:
			print(e)
			log(logging.ERROR, "Could not decipher the salt %s" % data["salt"])
			client.sendResult({"packet_id":nonce, "error": "Malformed salt", "timestamp": int(time.time()*1000)})
			return
		client.salt = decSalt

		timestamp = int(time.time()*1000)


		self.messageToBeReceived[newnonce] = {
			"type": "keychallenge",
			"timestamp": timestamp
		}
		
		client.sendResult({
			"packet_id": nonce,
			"new_packet_id": bytesToString(base64.b64encode(newnonce)),
			"type": "keychallenge", 
			"timestamp": timestamp,
			"result": "Correct challenge response",
			"response": bytesToString(base64.b64encode(response))
			})

	'''
		Establish a session key
	'''
	def establishSessionKey(self, data, client):
		log(logging.DEBUG, "%s" % json.dumps(data))

		if 'new_packet_id' not in data.keys() or 'ECDHpublickey' not in data.keys() or 'signature' not in data.keys():
			log(logging.ERROR, "Malformed message" + json.dumps(data))
			client.sendResult({"packet_id":data['new_packet_id'], "error": "wrong message format", "timestamp": int(time.time()*1000)})
			return

		# Get the nonce deciphered
		nonce = data['new_packet_id']
		try:
			decNonce = decipherAssymetricMessage(self.privateKey, base64.b64decode(stringToBytes(nonce)))
		except Exception as e:
			print(e)
			log(logging.ERROR, "Could not decipher the nonce %s" % nonce)
			client.sendResult({"packet_id":nonce, "error": "Malformed nonce", "timestamp": int(time.time()*1000)})
			return

		client_signature = base64.b64decode(stringToBytes(data["signature"]))

		# Create ECDH key pair
		ECDHprivate = ECDHgenerate()
		ECDH_publickey = ECDHprivate.public_key().public_bytes(encoding=serialization.Encoding.PEM, format=serialization.PublicFormat.SubjectPublicKeyInfo)

		# Calculate session key
		client_ECDHPublickeyserialized = base64.b64decode(stringToBytes(data["ECDHpublickey"]))
		client.sessionKey = ECDHcalculate(
			ECDHprivate.private_bytes(encoding=serialization.Encoding.PEM, format=serialization.PrivateFormat.PKCS8, encryption_algorithm=serialization.NoEncryption()), 
			client_ECDHPublickeyserialized)

		# Verify the signature of the client
		dataSigned = client_ECDHPublickeyserialized
		try:
			senderCCPublicKey = loadPubKey(dumpPublicKey(client.certificate.get_pubkey()))
			verifyCCSignature(senderCCPublicKey, client_signature, dataSigned, 'sha256')
		except Exception as e:
			print(e)
			log(logging.INFO, "Signature could not be verified")
			client.sendResult({"packet_id":nonce, "error": "Signature could not be verified", "timestamp": int(time.time()*1000)})
			return
		log(logging.INFO, "Server signature validated")

		try:
			signature = signMessage(self.privateKey, ECDH_publickey)
		except Exception as e:
			print(e)
			log(logging.INFO, "Signature could not be made")
			client.sendResult({"packet_id":nonce, "error": "Internal server error", "timestamp":  int(time.time()*1000)})
			return

		timestamp = int(time.time()*1000)

		message = {
			"packet_id": bytesToString(base64.b64encode(decNonce)),
			"type": "SessionParameters",
			"timestamp": timestamp,
			"ECDHpublickey": bytesToString(base64.b64encode(ECDH_publickey)),
			"result": "Session key established",
			"signature": bytesToString(base64.b64encode(signature))
		}
		client.sendResult(message)
		log(logging.INFO, "Got session key: %s" % client.sessionKey)

		# Calculate the UUID of the user
		uuid = digestSHA256(dumpPublicKey(client.certificate.get_pubkey()))
		client.uuid = uuid

		# If user exists, load its information based on the uuid
		lc = client.loadClient(bytesToString(base64.b64encode(uuid)))
		client.canCommunicate = True

	'''
		Creates a new user and stores its public key
	'''
	def processCreate(self, data, client):
		log(logging.DEBUG, "%s" % json.dumps(data))

		# If client did not authenticate, can't communicate
		if client.canCommunicate == False:
			log(logging.ERROR, "Client didn't authenticate")
			return

		nonce = data['packet_id']

		# Decipher the nonce to send to client
		try:
			decNonce = decipherAssymetricMessage(self.privateKey, base64.b64decode(nonce))
		except Exception as e:
			print(e)
			log(logging.ERROR, "Could not decipher the nonce %s" % nonce)
			client.sessionKey = client.sendResult({"packet_id":nonce, "error": "Malformed nonce", "timestamp": int(time.time()*1000)}, client.sessionKey, client.salt)
			return

		if 'signature' not in data.keys():
			log(logging.ERROR, "No \"signature\" field in \"create\" message: " +
				json.dumps(data))
			client.sessionKey = client.sendResult({"packet_id":bytesToString(base64.b64encode(decNonce)), "error": "wrong message format", "timestamp": int(time.time()*1000)}, client.sessionKey, client.salt)
			return

		# Check if user already exists
		if self.registry.userExists(bytesToString(base64.b64encode(client.uuid))):
			log(logging.ERROR, "User already exists: " + json.dumps(data))
			client.sessionKey = client.sendResult({"packet_id":bytesToString(base64.b64encode(decNonce)), "error": "uuid already exists", "timestamp": int(time.time()*1000)}, client.sessionKey, client.salt)
			return


		if "RSAPublicKey" not in data.keys():
			log(logging.ERROR, "RSA Public Key not on packet: " + json.dumps(data))
			client.sessionKey = client.sendResult({"packet_id":bytesToString(base64.b64encode(decNonce)), "error": "RSA Public Key not sent", "timestamp": int(time.time()*1000)}, client.sessionKey, client.salt)
			return

		# Verify the signature of client
		try:
			verifyCCSignature(loadPubKey(dumpPublicKey(client.certificate.get_pubkey())), base64.b64decode(stringToBytes(data["signature"])), base64.b64decode(stringToBytes(data["RSAPublicKey"])), 'sha256')
		except Exception as e:
			print(e)
			log(logging.ERROR, "Could not validate the signature of the message")
			client.sessionKey = client.sendResult({"packet_id":bytesToString(base64.b64encode(decNonce)), "error": "Signature could not be validated", "timestamp": int(time.time()*1000)}, client.sessionKey, client.salt)
			return

		# Load and store the client public key
		try:
			client.pubKey = loadPublicKey(base64.b64decode(stringToBytes(data["RSAPublicKey"])))
		except Exception as e:
			print(e)
			log(logging.ERROR, "RSA Public Key could not be read: " + json.dumps(data))
			client.sessionKey = client.sendResult({"packet_id":bytesToString(base64.b64encode(decNonce)), "error": "Malformed RSA Public Key", "timestamp": int(time.time()*1000)}, client.sessionKey, client.salt)
			return

		timestamp = int(time.time()*1000)
		
		userDescription = {"uuid": bytesToString(base64.b64encode(client.uuid)), "RSAPublicKey": data["RSAPublicKey"], "Certificate": bytesToString(base64.b64encode(dumpCertificate(client.certificate)))}

		me = self.registry.addUser(userDescription)
		client.id = me.id
		client.sessionKey = client.sendResult({
			"packet_id": bytesToString(base64.b64encode(decNonce)),
			"result": me.id,
			"timestamp": timestamp}, client.sessionKey, client.salt)

	'''
		Lists all users
	'''
	def processList(self, data, client):
		log(logging.DEBUG, "%s" % json.dumps(data))

		# If client did not authenticate, can't communicate
		if client.canCommunicate == False:
			log(logging.ERROR, "Client didn't authenticate")
			return

		nonce = data['packet_id']

		timestamp = int(time.time()*1000)
		try:
			decNonce = decipherAssymetricMessage(self.privateKey, base64.b64decode(nonce))
		except Exception as e:
			print(e)
			log(logging.ERROR, "Could not decipher the nonce %s" % nonce)
			client.sessionKey = client.sendResult({"packet_id":nonce, "error": "Malformed nonce", "timestamp": timestamp}, client.sessionKey, client.salt)
			return

		if 'id' not in data.keys():
			log(logging.ERROR, "No \"id\" field in \"processList\" message: " + json.dumps(data))
			client.sessionKey = client.sendResult({"packet_id":bytesToString(base64.b64encode(decNonce)), "error": "wrong message format", "timestamp": timestamp}, client.sessionKey, client.salt)
			return

		user = int(data['id'])

		if user!=client.id:
			log(logging.ERROR, "ID does not match the user: " + json.dumps(data))
			client.sessionKey = client.sendResult({"packet_id":bytesToString(base64.b64encode(decNonce)), "error": "ID does not match the user", "timestamp": timestamp}, client.sessionKey, client.salt)
			return

		user = 0  # 0 means all users
		userStr = "all users"
		if 'Targetid' in data.keys():
			user = int(data['Targetid'])
			userStr = "user%d" % user

		log(logging.DEBUG, "List %s" % userStr)

		userList = self.registry.listUsers(user)

		# For each user, sign the certificate and the public key combined
		if userList!=None:
			for user in userList:
				pubK = base64.b64decode(stringToBytes(user["RSAPublicKey"]))
				certificate = base64.b64decode(stringToBytes(user["Certificate"]))

				try:
					signature = signMessage(self.privateKey, pubK+certificate)
				except Exception as e:
					print(e)
					log(logging.INFO, "Signature could not be made to certificate and public key of user")
					client.sendResult({"packet_id":bytesToString(base64.b64encode(decNonce)), "error": "Internal server error", "timestamp":  timestamp})
					return

				user["signature"] = bytesToString(base64.b64encode(signature))

		client.sessionKey = client.sendResult({
			"packet_id":bytesToString(base64.b64encode(decNonce)),
			"result": userList,
			"timestamp": timestamp}, client.sessionKey, client.salt)

	'''
		Returns the new messages for a user
	'''
	def processNew(self, data, client):
		log(logging.DEBUG, "%s" % json.dumps(data))

		# If client did not authenticate, can't communicate
		if client.canCommunicate == False:
			log(logging.ERROR, "Client didn't authenticate")
			return

		nonce = data['packet_id']

		timestamp = int(time.time()*1000)
		try:
			decNonce = decipherAssymetricMessage(self.privateKey, base64.b64decode(nonce))
		except Exception as e:
			print(e)
			log(logging.ERROR, "Could not decipher the nonce %s" % nonce)
			client.sessionKey = client.sendResult({"packet_id":nonce, "error": "Malformed nonce", "timestamp": timestamp}, client.sessionKey, client.salt)
			return

		if 'id' not in data.keys():
			log(logging.ERROR, "No \"id\" field in \"processNew\" message: " +
				json.dumps(data))
			client.sessionKey = client.sendResult({"packet_id":bytesToString(base64.b64encode(decNonce)), "error": "wrong message format", "timestamp": timestamp}, client.sessionKey, client.salt)
			return

		user = int(data['id'])

		if user!=client.id:
			log(logging.ERROR,
				"ID does not match the user: " + json.dumps(data))
			client.sessionKey = client.sendResult({"packet_id":bytesToString(base64.b64encode(decNonce)), "error": "ID does not match the user", "timestamp": timestamp}, client.sessionKey, client.salt)
			return

		client.sessionKey = client.sendResult(
			{"packet_id":bytesToString(base64.b64encode(decNonce)),
			"result": self.registry.userNewMessages(user),
			"timestamp": timestamp}, client.sessionKey, client.salt)

	'''
		Returns the received and sent messages from the user
	'''
	def processAll(self, data, client):
		log(logging.DEBUG, "%s" % json.dumps(data))

		# If client did not authenticate, can't communicate
		if client.canCommunicate == False:
			log(logging.ERROR, "Client didn't authenticate")
			return

		nonce = data['packet_id']

		timestamp = int(time.time()*1000)
		try:
			decNonce = decipherAssymetricMessage(self.privateKey, base64.b64decode(nonce))
		except Exception as e:
			print(e)
			log(logging.ERROR, "Could not decipher the nonce %s" % nonce)
			client.sessionKey = client.sendResult({"packet_id":nonce, "error": "Malformed nonce", "timestamp": timestamp}, client.sessionKey, client.salt)
			return

		if 'id' not in data.keys():
			log(logging.ERROR, "No \"id\" field in \"processNew\" message: " +
				json.dumps(data))
			client.sessionKey = client.sendResult({"packet_id":bytesToString(base64.b64encode(decNonce)), "error": "wrong message format", "timestamp": timestamp}, client.sessionKey, client.salt)
			return

		user = int(data['id'])

		if user!=client.id:
			log(logging.ERROR,
				"ID does not match the user: " + json.dumps(data))
			client.sessionKey = client.sendResult({"packet_id":bytesToString(base64.b64encode(decNonce)), "error": "ID does not match the user", "timestamp": timestamp}, client.sessionKey, client.salt)
			return

		client.sessionKey = client.sendResult({
			"packet_id":bytesToString(base64.b64encode(decNonce)),
			"result": [self.registry.userAllMessages(user),self.registry.userSentMessages(user)],
			"timestamp": timestamp}, client.sessionKey, client.salt)

	'''
		Returns the public key of a client
	'''
	def processGetPublicKey(self, data, client):
		log(logging.DEBUG, "%s" % json.dumps(data))

		nonce = data['packet_id']
		timestamp = int(time.time()*1000)

		try:
			decNonce = decipherAssymetricMessage(self.privateKey, base64.b64decode(nonce))
		except Exception as e:
			print(e)
			log(logging.ERROR, "Could not decipher the nonce %s" % nonce)
			client.sessionKey = client.sendResult({"packet_id":nonce, "error": "Malformed nonce", "timestamp": timestamp}, client.sessionKey, client.salt)
			return

		if 'id' not in data.keys():
			log(logging.ERROR, "No \"id\" field in \"processNew\" message: " +
				json.dumps(data))
			client.sessionKey = client.sendResult({"packet_id":bytesToString(base64.b64encode(decNonce)), "error": "wrong message format", "timestamp": timestamp}, client.sessionKey, client.salt)
			return

		user = int(data['id'])

		if user!=client.id:
			log(logging.ERROR,
				"ID does not match the user: " + json.dumps(data))
			client.sessionKey = client.sendResult({"packet_id":bytesToString(base64.b64encode(decNonce)), "error": "ID does not match the user", "timestamp": timestamp}, client.sessionKey, client.salt)
			return


		if "receiverID" not in data:
			log(logging.ERROR,
				"Badly formated \"getPublicKey\" message: " + json.dumps(data))
			client.sessionKey = client.sendResult({"packet_id":bytesToString(base64.b64encode(decNonce)), "error": "wrong message format", "timestamp": timestamp}, client.sessionKey, client.salt)

		recUID = data["receiverID"]

		if not isinstance(recUID, int):
			log(logging.ERROR, "No valid \"receiverUUID\" field in \"getPublicKey\" message: " +
				json.dumps(data))
			client.sessionKey = client.sendResult({"packet_id":bytesToString(base64.b64encode(decNonce)), "error": "wrong message format", "timestamp": timestamp}, client.sessionKey, client.salt)
			return


		if not self.registry.userExists(recUID):
			log(logging.ERROR,
				"Unknown source id for \"getPublicKey\" message: " + json.dumps(data))
			client.sessionKey = client.sendResult({"packet_id":bytesToString(base64.b64encode(decNonce)), "error": "wrong parameters", "timestamp": timestamp}, client.sessionKey, client.salt)
			return

		receiverUser = self.registry.getUser(recUID)
		assert receiverUser != None

		publicKey = receiverUser.description["RSAPublicKey"]
		try:
			pksignature = signMessage(self.privateKey, base64.b64decode(stringToBytes(publicKey)))
		except Exception as e:
			print(e)
			log(logging.INFO, "Signature to the public key of the destination could not be made")
			client.sessionKey = client.sendResult({"packet_id":bytesToString(base64.b64encode(decNonce)), "error": "Internal server error", "timestamp": timestamp}, client.sessionKey, client.salt)
			return

		client.sessionKey = client.sendResult({
			"packet_id":bytesToString(base64.b64encode(decNonce)),
			"PublicKey": publicKey,
			"Signature": bytesToString(base64.b64encode(pksignature)),
			"timestamp": timestamp,
			"result": "Public Key sent"
			}, client.sessionKey, client.salt)

	'''
		Process sent message from client
	'''
	def processSend(self, data, client):
		log(logging.DEBUG, "%s" % json.dumps(data))

		nonce = data['packet_id']
		timestamp = int(time.time()*1000)

		try:
			decNonce = decipherAssymetricMessage(self.privateKey, base64.b64decode(nonce))
		except Exception as e:
			print(e)
			log(logging.ERROR, "Could not decipher the nonce %s" % nonce)
			client.sessionKey = client.sendResult({"packet_id":nonce, "error": "Malformed nonce", "timestamp": timestamp}, client.sessionKey, client.salt)
			return

		if not set(data.keys()).issuperset(set({'src', 'dst', 'msg', 'copy', 'timestamp', 'signature'})):
			log(logging.ERROR,
				"Badly formated \"send\" message: " + json.dumps(data))
			client.sessionKey = client.sendResult({"packet_id":bytesToString(base64.b64encode(decNonce)), "error": "wrong message format", "timestamp": timestamp}, client.sessionKey, client.salt)
			return

		srcId = int(data['src'])
		dstId = int(data['dst'])
		msg = str(data['msg'])
		copy = str(data['copy'])

		if srcId != client.id:
			log(logging.ERROR,
				"ID does not match the user: " + json.dumps(data))
			client.sessionKey = lient.sendResult({"packet_id":bytesToString(base64.b64encode(decNonce)), "error": "ID does not match the user", "timestamp": timestamp}, client.sessionKey, client.salt)
			return

		if not self.registry.userExists(srcId):
			log(logging.ERROR,
				"Unknown source id for \"send\" message: " + json.dumps(data))
			client.sessionKey = client.sendResult({"packet_id":bytesToString(base64.b64encode(decNonce)), "error": "wrong parameters", "timestamp": timestamp}, client.sessionKey, client.salt)
			return

		if not self.registry.userExists(dstId):
			log(logging.ERROR,
				"Unknown destination id for \"send\" message: " + json.dumps(data))
			client.sessionKey = client.sendResult({"packet_id":bytesToString(base64.b64encode(decNonce)), "error": "wrong parameters", "timestamp": timestamp}, client.sessionKey, client.salt)
			return
			
		# Save message and copy
		response = self.registry.sendMessage(srcId, dstId, {"message": msg, "timestamp": data["timestamp"], "signature": data["signature"]}, copy)

		client.sessionKey = client.sendResult({
			"packet_id":bytesToString(base64.b64encode(decNonce)),
			"result": response,
			"timestamp": timestamp}, client.sessionKey, client.salt)

	'''
		Process receive message
	'''
	def processRecv(self, data, client):
		log(logging.DEBUG, "%s" % json.dumps(data))

		nonce = data['packet_id']
		timestamp = int(time.time()*1000)

		try:
			decNonce = decipherAssymetricMessage(self.privateKey, base64.b64decode(nonce))
		except Exception as e:
			print(e)
			log(logging.ERROR, "Could not decipher the nonce %s" % nonce)
			client.sessionKey = client.sendResult({"packet_id":nonce, "error": "Malformed nonce", "timestamp": timestamp}, client.sessionKey, client.salt)
			return

		if not set({'id', 'msg'}).issubset(set(data.keys())):
			log(logging.ERROR, "Badly formated \"recv\" message: " +
				json.dumps(data))
			client.sessionKey = client.sendResult({"packet_id":bytesToString(base64.b64encode(decNonce)), "error": "wrong message format", "timestamp": timestamp}, client.sessionKey, client.salt)
			return

		fromId = int(data['id'])
		msg = str(data['msg'])

		if fromId!=client.id:
			log(logging.ERROR, "ID does not match the user: " + json.dumps(data))
			client.sessionKey = client.sendResult({"packet_id":bytesToString(base64.b64encode(decNonce)), "error": "ID does not match the user", "timestamp": timestamp}, client.sessionKey, client.salt)
			return

		if not self.registry.userExists(fromId):
			log(logging.ERROR,
				"Unknown source id for \"recv\" message: " + json.dumps(data))
			client.sessionKey = client.sendResult({"packet_id":bytesToString(base64.b64encode(decNonce)), "error": "wrong parameters", "timestamp": timestamp}, client.sessionKey, client.salt)
			return

		if not self.registry.messageExists(fromId, msg):
			log(logging.ERROR,
				"Unknown source msg for \"recv\" message: " + json.dumps(data))
			client.sessionKey = client.sendResult({"packet_id":bytesToString(base64.b64encode(decNonce)), "error": "wrong parameters", "timestamp": timestamp}, client.sessionKey, client.salt)
			return

		# Read message
		response = self.registry.recvMessage(fromId, msg)

		# Get the client public key to send to validate signature
		clientSender = self.registry.getUser(int(response[0]))
		assert clientSender != None

		certificate = loadCertificate(base64.b64decode(stringToBytes(clientSender.description["Certificate"])))
		senderPublicKey = dumpPublicKey(certificate.get_pubkey())

		# Sign the nonce sent to user
		message_nonce = generateNonce()
		try:
			nonce_signature = signMessage(self.privateKey, message_nonce)
		except Exception as e:
			print(e)
			log(logging.INFO, "Signature could not be done to nonce")
			client.sessionKey = client.sendResult({"packet_id":bytesToString(base64.b64encode(decNonce)), "error": "Internal server error", "timestamp": timestamp}, client.sessionKey, client.salt)
			return

		try:
			publicKeySignature = signMessage(self.privateKey, senderPublicKey)
		except Exception as e:
			print(e)
			log(logging.INFO, "Signature could not be done to public key")
			client.sessionKey = client.sendResult({"packet_id":bytesToString(base64.b64encode(decNonce)), "error": "Internal server error", "timestamp": timestamp}, client.sessionKey, client.salt)
			return

		timestamp = int(time.time()*1000)

		self.receipt[message_nonce] = {"timestamp": timestamp}
		client.sessionKey = client.sendResult({
			"packet_id":bytesToString(base64.b64encode(decNonce)),
			"result": response,
			"timestamp": timestamp,
			"msgnonce": bytesToString(base64.b64encode(message_nonce)),
			"senderPublicKey": bytesToString(base64.b64encode(senderPublicKey)),
			"signatureNonce": bytesToString(base64.b64encode(nonce_signature)),
			"signaturePublicKey": bytesToString(base64.b64encode(publicKeySignature))}, client.sessionKey, client.salt
			)

	'''
		Process receipt
	'''
	def processReceipt(self, data, client):
		log(logging.DEBUG, "%s" % json.dumps(data))

		nonce = data['packet_id']
		timestamp = int(time.time()*1000)

		if not set({'id', 'msg', 'receipt', 'timestamp'}).issubset(set(data.keys())):
			log(logging.ERROR, "Badly formated \"receipt\" message: " +
				json.dumps(data))
			return

		# Check if the received nonce corresponds to a saved nonce
		msgnonce = base64.b64decode(stringToBytes(nonce))
		if(msgnonce not in self.receipt):
			log(logging.ERROR, "Client sent receipt with invalid packet_id: %s" % data)
			return

		message = self.receipt[msgnonce]
		del self.receipt[msgnonce]

		# Check if the message was sent more than 10 seconds ago
		# If so, discard message
		if(data['timestamp']-message['timestamp']<0 or data['timestamp']-message['timestamp']>CLIENT_MAX_RESPONSE_TIME*1000):
			log(logging.ERROR, "Client sent receipt with late timestamp: %s; Request: %s" % (data['timestamp'], message['timestamp']))
			return
		
		fromId = int(data["id"])
		msg = str(data['msg'])
		receipt = str(data['receipt'])

		if fromId!=client.id:
			log(logging.ERROR, "ID does not match the user: " + json.dumps(data))
			return

		if not self.registry.messageWasRed(str(fromId), msg):
			log(logging.ERROR, "Unknown, or not yet red, message for \"receipt\" request " + json.dumps(data))
			return

		self.registry.storeReceipt(fromId, msg, receipt, data['timestamp'])

	'''
		Process status 
	'''
	def processStatus(self, data, client):
		log(logging.DEBUG, "%s" % json.dumps(data))

		nonce = data['packet_id']
		timestamp = int(time.time()*1000)

		try:
			decNonce = decipherAssymetricMessage(self.privateKey, base64.b64decode(nonce))
		except Exception as e:
			print(e)
			log(logging.ERROR, "Could not decipher the nonce %s" % nonce)
			client.sessionKey = client.sendResult({"packet_id":nonce, "error": "Malformed nonce", "timestamp": timestamp}, client.sessionKey, client.salt)
			return

		if not set({'id', 'msg'}).issubset(set(data.keys())):
			log(logging.ERROR, "Badly formated \"status\" message: " +
				json.dumps(data))
			client.sessionKey = client.sendResult({"packet_id":bytesToString(base64.b64encode(decNonce)), "error": "wrong message format", "timestamp": timestamp}, client.sessionKey, client.salt)
			return
		
		fromId = int(data['id'])
		msg = str(data["msg"])

		if fromId!=client.id:
			log(logging.ERROR,
				"ID does not match the user: " + json.dumps(data))
			client.sessionKey = client.sendResult({"packet_id":bytesToString(base64.b64encode(decNonce)), "error": "ID does not match the user", "timestamp": timestamp}, client.sessionKey, client.salt)
			return


		if(not self.registry.copyExists(fromId, msg)):
			log(logging.ERROR, "Unknown message for \"status\" request: " + json.dumps(data))
			client.sessionKey = client.sendResult({"packet_id":bytesToString(base64.b64encode(decNonce)), "error": "wrong parameters", "timestamp": timestamp}, client.sessionKey, client.salt)
			return

		response = self.registry.getReceipts(fromId, msg)

		# For each receipt, send the public key of the client
		# Signed by the server
		for receipt in response["receipts"]:

			# Get the client public key to send to validate receipt
			clientReceived = self.registry.getUser(int(receipt["id"]))
			assert clientReceived != None

			certificate = loadCertificate(base64.b64decode(stringToBytes(clientReceived.description["Certificate"])))
			receiptClientPublicKey = dumpPublicKey(certificate.get_pubkey())

			try:
				publicKeySignature = signMessage(self.privateKey, receiptClientPublicKey)
			except Exception as e:
				print(e)
				log(logging.INFO, "Signature could not be done to public key")
				client.sessionKey = client.sendResult({"packet_id":bytesToString(base64.b64encode(decNonce)), "error": "Internal server error", "timestamp": timestamp}, client.sessionKey, client.salt)
				return
			receipt.update({"PublicKey": bytesToString(base64.b64encode(receiptClientPublicKey)), "Signature": bytesToString(base64.b64encode(publicKeySignature))})
		
		client.sessionKey = client.sendResult({"packet_id":bytesToString(base64.b64encode(decNonce)), "result": response, "timestamp": timestamp}, client.sessionKey, client.salt)
