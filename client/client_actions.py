#
# Diogo Daniel Soares Ferreira N 76504
# Luis Davide Jesus Leira N 76514
#
# Segurity Messaging Repository System 2017-2018

import json
import logging
import time
from security_actions import *
from log import *
from aux_functions import *
import base64
from publicKeyCache import PublicKeyCache
from CCInterface import *
from OpenSSL import crypto
from users import *

# Maximum server response time in seconds
SERVER_MAX_RESPONSE_TIME = 10

class bcolors:
	'''
		Colors for standard output
	'''
	HEADER = '\033[95m'
	OKBLUE = '\033[94m'
	OKGREEN = '\033[92m'
	WARNING = '\033[93m'
	FAIL = '\033[91m'
	ENDC = '\033[0m'
	BOLD = '\033[1m'
	UNDERLINE = '\033[4m'

class ClientActions:

	def __init__(self, server, user):
		self.server = server
		self.user = user

		# Dictionary with the ID of the messages to be received
		# and its parameters
		self.messageToBeReceived = {}

		self.serverPublicKey = None
		self.sessionKey = None
		self.salt=None

		# ECDH
		self.ECDHprivate = None

		# Cache with the public keys of other users
		self.publicKeyCache = PublicKeyCache()

		# Flag to know if it already has established connection with the server
		# And can communicate with the session key
		self.canCommunicate = False



	
	def readMessage(self, data):
		'''
			Read and decide what to do with a message from the server
		'''
		
		try:
			log(logging.INFO, "HANDLING message from server %s: %r" % (self.server, data))

			try:
				obj = json.loads(data)
			except:
				logging.exception("Invalid message")
				return

			if not isinstance(obj, dict):
				log(logging.ERROR, "Invalid message format")
				return


			if 'packet_id' not in obj:
				log(logging.ERROR, "Server sent message without packet_id: %s" % obj)
				return
			
			current_time = int(time.time()*1000)
			nonce = base64.b64decode(obj['packet_id'])

			# If the message was sent from more than 10 seconds ago,
			# Or the timestamp is from the future,
			# Discard message
			if 'timestamp' in obj:
				if(current_time-obj['timestamp']<0 or current_time-obj['timestamp']>SERVER_MAX_RESPONSE_TIME*1000):
					log(logging.ERROR, "Server sent message with wrong timestamp: %s; Current: %s" % (obj['timestamp'], current_time))
					return
			else:
				log(logging.ERROR, "Server sent message without timestamp: %s" % obj)
				return

			if nonce not in self.messageToBeReceived:
				log(logging.ERROR, "Server sent message with invalid packet_id: %s" % obj)
				return
			

			# Retrieve the message from the messages to be received
			# And remove it from the list
			message = self.messageToBeReceived[nonce]
			del self.messageToBeReceived[nonce]

			# If the request was sent more than 10 seconds ago,
			# discard message
			if(obj['timestamp']-message['timestamp']<0 or obj['timestamp']-message['timestamp']>SERVER_MAX_RESPONSE_TIME*1000):
				log(logging.ERROR, "Server sent response with late timestamp: %s; Request: %s" % (message['timestamp'], obj['timestamp']))
				return

			if 'error' in obj:
				log(logging.ERROR, "Server sent: Error: %s" % obj['error'])
				return

			if 'result' in obj:
				log(logging.INFO, "Server sent: Result: %s" % obj['result'])

				if message['type']=='list':
					self.receiveList(obj['result'])

				if message['type']=='new':
					self.receiveNew(obj['result'])

				if message['type']=='all':
					self.receiveAll(obj['result'])

				if message['type']=='send':
					self.receiveSend(obj['result'])
				
				if message['type']=="recv":
					self.checkReceive(obj, message['msg'])

				elif message['type']=="getPublicKey":
					self.processSend(message['dst'], message['msg'], obj['PublicKey'], obj['Signature'])
				
				elif message['type']=="status":
					self.receiveStatus(obj['result'])

				elif message['type']=="key":
					self.receiveServerKey(obj)

				elif message['type']=="create":
					self.receiveCreate(obj['result'])

				elif message['type']=="keychallenge":
					self.initiateSessionKeyEstablishment(obj, message['challenge'])
				
				elif message['type']=="SessionParameters":
					self.createSessionKey(obj)
				return

		except Exception as e:
			logging.exception("Could not read message")



	'''
		Key exchange phase 1
	'''
	def initiateKeyExchange(self):
		# Generate nonce
		nonce = generateNonce()

		# Get CC Auth Certificate
		cert = getAuthCertificate()

		cert_object = loadCertificate(cert)

		# CC Certificates
		CCRoot, CCInterm = getCertificates()
		# Trusted store certificates
		storedRoot, storedInterm = get_cert_keystore()

		allRoot = CCRoot + storedRoot
		allInterm = CCInterm + storedInterm

		# Get path to client certificate
		path = getCertificatePath(cert_object, allRoot, allInterm)
		# Serialize certificates
		serialized_path = {}
		for certificate in path:
			serialized_path[str(certificate)] = bytesToString(dumpCertificate(path[certificate]))
		serialized_path = stringToBytes(json.dumps(serialized_path))


		# Validate the certificate chain to be sent to server
		valid = validateCertificateChain(cert_object, path)
		
		if not valid:
			log(logging.ERROR, "Certificate chain is not valid: %s " % path)
			return

		# Get timestamp
		timestamp = int(time.time()*1000)


		message = {
			"packet_id": bytesToString(base64.b64encode(nonce)),
			"type": "key",
			"timestamp": timestamp,
			"certificate": bytesToString(base64.b64encode(cert)),
			"certificatechain": bytesToString(base64.b64encode(serialized_path))
		}

		
		self.messageToBeReceived[nonce] = {
			"type": "key",
			"timestamp": timestamp
		}
		
		
		self.server.sendMessage(message)
		

	'''
		Receive the server certificate (gather the public key) and signature
	'''
	def receiveServerKey(self, data):
		log(logging.DEBUG, "%s" % json.dumps(data))

		if "new_packet_id" not in data.keys() or "certificatechain" not in data.keys() or "challenge" not in data.keys() or "certificate" not in data.keys():
			log(logging.ERROR, "Malformed message" + json.dumps(data))
			return

		nonce = data['new_packet_id']
		# Generate new nonce
		newnonce = generateNonce()

		# Loads the certificate
		try:
			certBytes = base64.b64decode(stringToBytes(data["certificate"]))
			cert = loadCertificate(certBytes)
		except Exception as e:
			print(e)
			log(logging.ERROR, "Could not load the certificate: " + json.dumps(data))
			return

		# Validates the certificate chain
		certificatechain =  base64.b64decode(data["certificatechain"])
		certificatechainserialized = json.loads(bytesToString(certificatechain))

		path = {}
		for certificate in certificatechainserialized:
			path[int(certificate)] = loadCertificate(certificatechainserialized[certificate])
		valid = validateCertificateChain(cert, path)
		
		if not valid:
			log(logging.ERROR, "Certificate chain is not valid: %s " % path)
			return
		else:
			log(logging.INFO, "Server certificate chain validated")

		# Load the server public key
		try:
			self.serverPublicKey = loadPublicKey(dumpPublicKey(cert.get_pubkey()))
		except Exception as e:
			print(e)
			log(logging.ERROR, "Could not get the server public key from the certificate")
			return 

		log(logging.INFO, "Server public key gathered")

		# Answer the challenge
		challenge = base64.b64decode(stringToBytes(data["challenge"]))
		try:
			response = sign(challenge)
		except Exception as e:
			print(e)
			log(logging.ERROR, "Could not sign the challenge: %s " % dataSigned)
			return

		# Generate challenge
		challenge = os.urandom(32)

		# Generate salt for session key
		self.salt = os.urandom(16)

		# Cipher the salt to send to the server
		try:
			cipheredSalt = cipherAssymetricMessage(self.serverPublicKey, self.salt)
		except Exception as e:
			print(e)
			log(logging.ERROR, "Could not cipher the salt for the session key " + nonce)
			return
		
		timestamp = int(time.time()*1000)
		
		self.messageToBeReceived[newnonce] = {
			"type": "keychallenge",
			"timestamp": timestamp,
			"challenge": challenge
		}
		
		self.server.sendMessage({
			"packet_id": nonce,
			"new_packet_id": bytesToString(base64.b64encode(newnonce)),
			"type": "keychallenge", 
			"timestamp": timestamp,
			"challenge": bytesToString(base64.b64encode(challenge)),
			"response": bytesToString(base64.b64encode(response)),
			"salt": bytesToString(base64.b64encode(cipheredSalt))
			})

	'''
		If the result from server is correct, iniciate session key establishment
	'''
	def initiateSessionKeyEstablishment(self, data, stored_challenge):
		log(logging.DEBUG, "%s" % json.dumps(data))

		if "new_packet_id" not in data.keys() or "response" not in data.keys():
			log(logging.ERROR, "Malformed message" + json.dumps(data))
			return

		nonce = data['new_packet_id']
		# Generate new nonce
		newnonce = generateNonce()

		try:
			cipheredNonce = cipherAssymetricMessage(self.serverPublicKey, newnonce)
		except Exception as e:
			print(e)
			log(logging.ERROR, "Could not cipher the nonce " + nonce)
			return

		response = base64.b64decode(stringToBytes(data["response"]))

		# Check if response matches the challenge
		try:
			verifySigning(self.serverPublicKey, stored_challenge, response)
		except Exception as e:
			print(e)
			log(logging.INFO, "Signature could not be verified")
			return

		# Create ECDH key pair
		self.ECDHprivate = ECDHgenerate()
		ECDH_publickey = self.ECDHprivate.public_key().public_bytes(encoding=serialization.Encoding.PEM, format=serialization.PublicFormat.SubjectPublicKeyInfo)
		
		# Sign the message with the private key
		try:
			signature = sign(ECDH_publickey)
		except Exception as e:
			print(e)
			log(logging.ERROR, "Could not sign the packet: %s " % dataSigned)
			return

		timestamp = int(time.time()*1000)

		self.messageToBeReceived[newnonce] = {
			"type": "SessionParameters",
			"timestamp": timestamp
		}

		message = {
			"packet_id": nonce,
			"new_packet_id": bytesToString(base64.b64encode(cipheredNonce)),
			"type": "SessionParameters",
			"timestamp": timestamp,
			"ECDHpublickey": bytesToString(base64.b64encode(ECDH_publickey)),
			"signature": bytesToString(base64.b64encode(signature))
		}
		self.server.sendMessage(message)


	'''
		Creates the session key
	'''
	def createSessionKey(self, data):
		log(logging.DEBUG, "%s" % json.dumps(data))

		if "ECDHpublickey" not in data.keys() or 'signature' not in data.keys():
			log(logging.ERROR, "Malformed message" + json.dumps(data))
			return

		signature = base64.b64decode(stringToBytes(data["signature"]))
		client_ECDHPublickeyserialized = base64.b64decode(stringToBytes(data["ECDHpublickey"]))
		
		# Verify the signature of the server
		try:
			verifySigning(self.serverPublicKey, client_ECDHPublickeyserialized, signature)
		except Exception as e:
			print(e)
			log(logging.INFO, "Signature could not be verified")
			return

		self.sessionKey = ECDHcalculate(
			self.ECDHprivate.private_bytes(
				encoding=serialization.Encoding.PEM,
				format=serialization.PrivateFormat.PKCS8,
				encryption_algorithm=serialization.NoEncryption()
				),
			client_ECDHPublickeyserialized
		)
		log(logging.INFO, "Got session key: %s" % self.sessionKey)

		# If user does not have id, send create request
		if (self.user.id==None):
			self.processCreate()
		else:
			log(logging.INFO, "User with ID %s" % self.user.id)
			self.canCommunicate = True


	'''
		Create user in the server and send the public key
	'''
	def processCreate(self):

		# Cipher the Nonce with the public key of the server
		nonce = generateNonce()

		try:
			cipheredNonce = cipherAssymetricMessage(self.serverPublicKey, nonce)
		except Exception as e:
			print(e)
			log(logging.ERROR, "Could not cipher the nonce " + nonce)
			return

		# Serialize public key
		serializedPublicKey = serializePublicKey(self.user.publicKey)

		signature = sign(serializedPublicKey)

		timestamp = int(time.time()*1000)

		message = {
			"packet_id": bytesToString(base64.b64encode(cipheredNonce)),
			"type": "create",
			"timestamp": timestamp,
			"RSAPublicKey": bytesToString(base64.b64encode(serializedPublicKey)),
			"signature":bytesToString(base64.b64encode(signature))
		}

		self.messageToBeReceived[nonce] = {"type": "create", "timestamp": timestamp}
		self.sessionKey = self.server.sendMessage(message, self.sessionKey, self.salt)
		self.canCommunicate = True

	'''
		Save ID for the user
	'''
	def receiveCreate(self, aid):
			
		self.user.id = aid
		users = Users()
		users.saveUser(self.user)
		log(logging.INFO, "User ID saved with number %s" % aid)

	'''
		Sends a message to list all users or one user
	'''
	def processList(self, cid=None):

		nonce = generateNonce()
		timestamp = int(time.time()*1000)

		try:
			cipheredNonce = cipherAssymetricMessage(self.serverPublicKey, nonce)
		except Exception as e:
			print(e)
			log(logging.ERROR, "Could not cipher the nonce " + nonce)
			return
		
		if cid != None:
			
			if not isinstance (cid, int):
				log(logging.ERROR, "id field %s is not an integer." % cid)
				return
			
			message = {"packet_id": bytesToString(base64.b64encode(cipheredNonce)), "type": "list", "id": self.user.id, "Targetid": int(cid), "timestamp": timestamp}

		else:
			message = {"packet_id": bytesToString(base64.b64encode(cipheredNonce)), "type": "list", "id": self.user.id, "timestamp": timestamp}

		self.messageToBeReceived[nonce] = {"type": "list", "timestamp": timestamp}
		self.sessionKey = self.server.sendMessage(message, self.sessionKey, self.salt)

	'''
		Receive the response to a list packet
	'''
	def receiveList(self, result):
		if result != None:
			for item in result:
				aid = item["id"]
				if "description" in item:
					cert = item["description"]["Certificate"]
					pubKey = item["description"]["RSAPublicKey"]
				else:
					cert = item["Certificate"]
					pubKey = item["RSAPublicKey"]

				# Verify the signature of the server for each client certificate and public key
				try:
					verifySigning(self.serverPublicKey, base64.b64decode(stringToBytes(pubKey))+base64.b64decode(stringToBytes(cert)), base64.b64decode(stringToBytes(item["signature"])))
					log(logging.INFO, "Signature of certificate and public key of user verified")
				except Exception as e:
					print(e)
					log(logging.ERROR, "Signature of certificate and public key of user could not be verified")


				print (bcolors.OKBLUE + 'User ID: '+str(aid)+'\nCertificate: '+cert+'\nPublic Key:'+pubKey+'\n'+ bcolors.ENDC)

	'''
		Get the new messages received
	'''
	def processNew(self):

		nonce = generateNonce()

		try:
			cipheredNonce = cipherAssymetricMessage(self.serverPublicKey, nonce)
		except Exception as e:
			print(e)
			log(logging.ERROR, "Could not cipher the nonce " + nonce)
			return
		
		timestamp = int(time.time()*1000)
		message = {"packet_id": bytesToString(base64.b64encode(cipheredNonce)), "type": "new", "id": self.user.id, "timestamp": timestamp}
		self.messageToBeReceived[nonce] = {"type": "new", "timestamp": timestamp}
		self.sessionKey = self.server.sendMessage(message, self.sessionKey, self.salt)

	'''
		List of new messages
	'''
	def receiveNew(self, result):
		if result==[]:
			print (bcolors.OKBLUE + 'No new messages to be received\n'+ bcolors.ENDC)
		else:
			print (bcolors.OKBLUE + 'Messages:\n'+ bcolors.ENDC)

		for message in result:
			print(bcolors.OKBLUE + message + bcolors.ENDC)

	'''
		List of all messages to be received
	'''
	def processAll(self):

		nonce = generateNonce()

		try:
			cipheredNonce = cipherAssymetricMessage(self.serverPublicKey, nonce)
		except Exception as e:
			print(e)
			log(logging.ERROR, "Could not cipher the nonce " + nonce)
			return
		
		timestamp = int(time.time()*1000)
		message = {"packet_id": bytesToString(base64.b64encode(cipheredNonce)), "type": "all", "id": self.user.id, "timestamp": timestamp}
		self.messageToBeReceived[nonce] = {"type": "all", "timestamp": timestamp}
		self.sessionKey = self.server.sendMessage(message, self.sessionKey, self.salt)

	def receiveAll(self, result):
		received, sent = result

		if received==[]:
			print (bcolors.OKBLUE + 'No new messages be received\n'+ bcolors.ENDC)
		else:
			print (bcolors.OKBLUE + 'Messages received:\n'+ bcolors.ENDC)

		for message in received:
			print(bcolors.OKBLUE + message + bcolors.ENDC)

		if sent==[]:
			print (bcolors.OKBLUE + 'No new messages sent\n'+ bcolors.ENDC)
		else:
			print (bcolors.OKBLUE + 'Messages sent:\n'+ bcolors.ENDC)

		for message in sent:
			print(bcolors.OKBLUE + message + bcolors.ENDC)

	'''
		Get the destination public key
	'''
	def processGetPublicKey(self, dst, msg):

		if not isinstance (dst, int):
			log(logging.ERROR, "dst field  %s is not an integer." % dst)
			return

		# Check if public key exists on the cache
		pk = self.publicKeyCache.search(dst)
		if pk!=None:
			log(logging.INFO, "Key on cache")
			return self.processSend(dst, msg, pk)

		nonce = generateNonce()
		
		try:
			cipheredNonce = cipherAssymetricMessage(self.serverPublicKey, nonce)
		except Exception as e:
			print(e)
			log(logging.ERROR, "Could not cipher the nonce " + nonce)
			return

		timestamp = int(time.time()*1000)

		self.messageToBeReceived[nonce] = {
			"type": "getPublicKey",
			"timestamp": timestamp,
			"dst": int(dst),
			"msg": msg
		}

		message = {
			"packet_id": bytesToString(base64.b64encode(cipheredNonce)),
			"type": "getPublicKey",
			"timestamp": timestamp,
			"id": self.user.id,
			"receiverID": int(dst)
		}
		
		self.sessionKey = self.server.sendMessage(message, self.sessionKey, self.salt)

	'''
		Send message to another client
	'''
	def processSend(self, dst, msg, publicKey, signature=None):

		if not isinstance (dst, int):
			log(logging.ERROR, "dst field %s is not an integer." % dst)
			return

		# Verify if the signature is valid
		publicKeyBytes = base64.b64decode(stringToBytes(publicKey))
		if signature:
			try:
				verifySigning(self.serverPublicKey, publicKeyBytes, base64.b64decode(stringToBytes(signature)))
			except Exception as e:
				print(e)
				log(logging.INFO, "Signature of public key could not be verified")
				return
			log(logging.INFO, "Public key signature verified")

			# Add public key to cache
			self.publicKeyCache.add(dst, publicKey)

		# Load the public key
		try:
			RSAPublicKey = loadPublicKey(publicKeyBytes)
		except Exception as e:
			print(e)
			log(logging.ERROR, "RSA Public Key could not be read: " + json.dumps(publicKey))
			return

		nonce = generateNonce()

		try:
			cipheredNonce = cipherAssymetricMessage(self.serverPublicKey, nonce)
		except Exception as e:
			print(e)
			log(logging.ERROR, "Could not cipher the nonce " + nonce)
			return
		
		timestamp = int(time.time()*1000)

		# cipher the message with symmetric cipher
		try:
			key, iv, enc_message = cipherMessage(stringToBytes(msg))
		except Exception as e:
			print(e)
			log(logging.ERROR, "Could not cipher the message: %s" % msg)
			return

		# cipher the key and the IV with the public key of the receiver
		try:
			cipheredKeyIV = cipherAssymetricMessage(RSAPublicKey, key+iv)
		except Exception as e:
			log(logging.ERROR, "Could not cipher the Key and IV")
			return

		# cipher and assure integrity control of the copy of the message
		try:
			copyKey, copyIV, copyMessage = cipherMessageWithIntegrityCheck(message=stringToBytes(msg), key=None)
		except Exception as e:
			print(e)
			log(logging.ERROR, "Could not cipher the copy of the message " + msg)
			return

		# Only the sender can decipher its contents
		try:
			cipheredCopyKeyIV = cipherAssymetricMessage(self.user.publicKey, copyKey+copyIV)
		except Exception as e:
			print(e)
			log(logging.ERROR, "Could not cipher the Key and IV of the copy message")
			return

		# Sign the message with the private key
		try:
			sig = sign(stringToBytes(msg+str(timestamp)))
		except Exception as e:
			print(e)
			log(logging.ERROR, "Could not sign the message: %s " % msg+str(timestamp))
			return

		# Key and IV are appended to the message
		message = {
				"packet_id": bytesToString(base64.b64encode(cipheredNonce)), 
				"type": "send", 
				"src": int(self.user.id),
				"dst": int(dst),
				"msg": bytesToString(base64.b64encode(cipheredKeyIV+enc_message)),
				"copy": bytesToString(base64.b64encode(cipheredCopyKeyIV+copyMessage)),
				"timestamp": timestamp,
				"signature": bytesToString(base64.b64encode(sig))
				}

		self.messageToBeReceived[nonce] = {"type": "send", "timestamp": timestamp}
		self.sessionKey = self.server.sendMessage(message, self.sessionKey, self.salt)

	'''
		Receive send message from server
	'''
	def receiveSend(self, result):
		if result==[] or result==None:
			print (bcolors.OKBLUE + 'Error receiving the message\n'+ bcolors.ENDC)
		else:
			for idx, res in enumerate(result):
				if idx==0:
					print (bcolors.OKBLUE + 'Receiver message box id:'+ str(res) + bcolors.ENDC)
				else:
					print (bcolors.OKBLUE + 'Receipt message box id:'+ str(res) +bcolors.ENDC)
			
	'''
		Receive message
	'''
	def processRecv(self, msg):
		nonce = generateNonce()
		
		try:
			cipheredNonce = cipherAssymetricMessage(self.serverPublicKey, nonce)
		except Exception as e:
			print(e)
			log(logging.ERROR, "Could not cipher the nonce " + nonce)
			return

		timestamp = int(time.time()*1000)
		message = {
				"packet_id": bytesToString(base64.b64encode(cipheredNonce)),
				"type": "recv", 
				"id": self.user.id,
				"msg": str(msg),
				"timestamp": timestamp}
		self.messageToBeReceived[nonce] = {"type": "recv", "msg":str(msg), "timestamp": timestamp}
		self.sessionKey = self.server.sendMessage(message, self.sessionKey, self.salt)


	'''
		Check if the message received from the server can be read as a valid message
	'''
	def checkReceive(self, data, msg):
		log(logging.INFO, "Message received sucessfully: %s" % data)

		# Use the id of the message and the message to confirm the receipt
		msgbox_id = self.user.id
		msg_id = msg

		# Get the message and decipher it
		message_src, message_info = data['result']

		message_content = message_info['message']
		message = base64.b64decode(stringToBytes(message_content))
		
		# Extract the key and the IV and decipher the with the private key
		keyIV = message[0:256]
		try:
			decKeyIV = decipherAssymetricMessage(self.user.privateKey, keyIV)
		except Exception as e:
			print(e)
			log(logging.ERROR, "Could not decipher the Key and IV: %s" % data['result'])
			return

		# The first 32 bits are the key and the next 16 are the IV
		key = decKeyIV[0:32]
		iv = decKeyIV[32:48]
		try:
			message_decoded = bytesToString(decipherMessage(key, iv, message[256:]))
		except Exception as e:
			print(e)
			log(logging.ERROR, "Could not decipher the message: %s" % data['result'])
			return

		log(logging.INFO, "Message decoded from %s: %s" % (message_src, message_decoded))
		print (bcolors.OKBLUE + '"Message decoded from '+message_src+': '+message_decoded +bcolors.ENDC)
		
		# Get the public key and check if the signature is valid
		senderPublicKey = base64.b64decode(stringToBytes(data['senderPublicKey']))
		senderPublicKeySignature = base64.b64decode(stringToBytes(data['signaturePublicKey']))
		try:
			verifySigning(self.serverPublicKey, senderPublicKey, senderPublicKeySignature)
			log(logging.INFO, "Public key verified")
		except Exception as e:
			print(e)
			log(logging.INFO, "Public key could not be verified")
			return

		# Verify the signature of the message with the public key of the sender of the message
		try:
			senderPublicKey = loadPublicKey(senderPublicKey)
		except Exception as e:
			print(e)
			log(logging.ERROR, "Sender Public Key could not be read: " + publicKey)
			return

		try:
			signedData = stringToBytes(message_decoded+str(message_info['timestamp']))
			signature = base64.b64decode(stringToBytes(message_info['signature']))
			publicKeyOpenSSL = loadPubKey(serializePublicKey(senderPublicKey))
			verifyCCSignature(publicKeyOpenSSL, signature, signedData, "sha256")
			log(logging.INFO, "Message signature verified")
		except Exception as e:
			print(e)
			log(logging.INFO, "Message signature could not be verified")
			return

		# Verify if nonce was signed by server
		try:
			verifySigning(self.serverPublicKey, base64.b64decode(stringToBytes(data["msgnonce"])), base64.b64decode(stringToBytes(data["signatureNonce"])))
			log(logging.INFO, "Message nonce verified")
		except Exception as e:
			print(e)
			log(logging.INFO, "Message nonce could not be verified")
			return

		self.processReceipt(msg_id, data["msgnonce"], message_decoded)

	'''
		Send a receipt to the server
	'''
	def processReceipt(self, msg, msgnonce, plainTextMessage):
		
		timestamp = int(time.time()*1000)

		receiptSig = sign(stringToBytes(plainTextMessage+str(timestamp)))
		print (bcolors.OKBLUE + 'Receipt sent for message: '+ str(msg) +bcolors.ENDC)
		message = {
				"packet_id": msgnonce,
				"type": "receipt", 
				"id": self.user.id,
				"msg": str(msg),
				"receipt": bytesToString(base64.b64encode(receiptSig)),
				"timestamp": timestamp}
		self.sessionKey = self.server.sendMessage(message, self.sessionKey, self.salt)
	
	'''
		Process status
	'''
	def processStatus(self, msg):

		nonce = generateNonce()
		
		try:
			cipheredNonce = cipherAssymetricMessage(self.serverPublicKey, nonce)
		except Exception as e:
			print(e)
			log(logging.ERROR, "Could not cipher the nonce " + nonce)
			return

		timestamp = int(time.time()*1000)
		message = {
				"packet_id": bytesToString(base64.b64encode(cipheredNonce)),
				"type": "status", 
				"id": self.user.id,
				"msg": str(msg),
				"timestamp": timestamp}
		self.messageToBeReceived[nonce] = {"type": "status", "timestamp": timestamp}
		self.sessionKey = self.server.sendMessage(message, self.sessionKey, self.salt)

	'''
		Receive status message from server
	'''
	def receiveStatus(self, result):
		
		# Decipher the message received
		msg = base64.b64decode(result['msg'])
		
		# Extract the key and the IV and decipher them with the private key
		keyIV = msg[0:256]
		try:
			decKeyIV = decipherAssymetricMessage(self.user.privateKey, keyIV)
		except Exception as e:
			print(e)
			log(logging.ERROR, "Could not decipher the Key and IV of receipt: %s" % result)
			return

		# The first 32 bits are the key and the next 16 are the IV
		key = decKeyIV[0:32]
		iv = decKeyIV[32:48]
		try:
			message_decoded = bytesToString(decipherMessageWithIntegrityCheck(key, iv, msg[256:]))
		except Exception as e:
			print(e)
			log(logging.ERROR, "Could not decipher the message of receipt: %s" % result)
			return

		print (bcolors.OKBLUE + 'Message receipt received:'+ str(message_decoded) +bcolors.ENDC)


		# Verify the signature of the messages
		for receipt in result['receipts']:
			log(logging.INFO, "Message receipt received from %s with timestamp %s" % (receipt['id'], receipt['date']))
			
			# Get the public key and check if the signature is valid
			receiverPublicKey = base64.b64decode(stringToBytes(receipt['PublicKey']))
			receiverPublicKeySignature = base64.b64decode(stringToBytes(receipt['Signature']))
			
			# Validate the signature made by the server to the public key
			try:
				verifySigning(self.serverPublicKey, receiverPublicKey, receiverPublicKeySignature)
				log(logging.INFO, "Public key verified")
			except Exception as e:
				print(e)
				log(logging.INFO, "Public key could not be verified")
				return

			# Load the receiver public key
			try:
				receiverPublicKey = loadPublicKey(receiverPublicKey)
			except Exception as e:
				print(e)
				log(logging.ERROR, "Receiver Public Key could not be loaded: " + receiverPublicKey)
				return

			# Check if the receipt can be validated with the public key of the receiver of the message
			try:
				signedData = stringToBytes(message_decoded+str(receipt['date']))
				signature = base64.b64decode(stringToBytes(receipt['receipt']))
				publicKeyOpenSSL = loadPubKey(serializePublicKey(receiverPublicKey))
				verifyCCSignature(publicKeyOpenSSL, signature, signedData, "sha256")
				log(logging.INFO, "Message receipt verified: %s" % receipt)
			except Exception as e:
				print(e)
				log(logging.ERROR, "Message receipt could not be verified: %s" % receipt)

