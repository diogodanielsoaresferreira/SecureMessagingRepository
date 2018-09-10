#
# Diogo Daniel Soares Ferreira N 76504
# Luis Davide Jesus Leira N 76514
#
# Segurity Messaging Repository System 2017-2018

import os
from log import *
from security_actions import *
from CCInterface import *
from cryptography.exceptions import *
import json

class User:
	def __init__(self, publicKey, privateKey, uuid, aid=None, username=None):
		self.publicKey = publicKey
		self.privateKey = privateKey
		self.uuid = uuid
		self.id = aid
		self.username = username

		# Temporary values only used to register a user
		self.cipheredPrivateKey = None
		self.derivedPassword = None
		self.iv = None

class Users:
	def __init__(self):
		pass

	# Create user and keys, but it does not save them
	def createUser(self, username, password):
		assert self.checkIfUserExists(username)==False

		# Get the citizen card certificate
		# Could not use directly the public key from the CC
		# Because is slightly different from loading the certificate
		# And hash is different from the calculated on the server
		try:
			cert = getAuthCertificate()
		except Exception as e:
			print(e)
			log(logging.ERROR, "Could not get the certificate from the smartcard")
			return False

		authPubKey = dumpPublicKey(loadCertificate(cert).get_pubkey())

		# Calculate the UUID
		uuid = digestSHA256(authPubKey)

		if self.checkIfUUIDExists(uuid):
			return False

		privkey, publickey = generateKeys()
		user = User(publickey, privkey, uuid, None, username)


		user.derivedPassword, user.iv = deriveKey(stringToBytes(password))

		# Cipher private key and store it to later save
		# Without the need of inserting the password again
		user.cipheredPrivateKey = serializePrivateKey(privkey, stringToBytes(password))

		return user

	# Save user locally
	def saveUser(self, user):
		assert self.checkIfUserExists(user.username)==False
		
		# Create a folder with users
		usersDir = "users"
		if not os.path.exists(usersDir):
			os.mkdir(usersDir)

		# Create a folder with username
		userDir = usersDir+"/"+user.username
		if not os.path.exists(userDir):
			os.mkdir(userDir)

		# Create a folder keystore
		keyDir = userDir+"/keystore"
		if not os.path.exists(keyDir):
			os.mkdir(keyDir)

		# Save keys into keystore
		saveKeyOnFile(user.cipheredPrivateKey, keyDir+"/privKey.key")
		self.savePublicKey(user.username, user.publicKey)

		self.saveUserDescription(user.username, {'uuid':bytesToString(base64.b64encode(user.uuid)), 'password': bytesToString(base64.b64encode(user.iv+user.derivedPassword)), 'id':user.id})

		# Delete the stored temporary values for security reasons
		user.cipheredPrivateKey = None
		user.derivedPassword = None
		user.iv = None
		return True

	# Check if user already exists
	def checkIfUserExists(self, username):
		path = "users/"

		# Create a folder with username
		userDir = path+username

		return os.path.exists(userDir)

	# Check if UUID exists
	def checkIfUUIDExists(self, uuid):
		path = "users/"

		if not os.path.exists(path):
			return False

		for f in os.listdir(path):
			with open(path+f+"/description", "r") as description:
				content = description.read()

			desc = json.loads(content)
			if base64.b64decode(stringToBytes(desc["uuid"]))==uuid:
				print("UUID is already registered on this client")
				return True

		return False

	# Get a user object
	def getUser(self, username, password):
		
		if not self.checkIfUserExists(username):
			return

		path = "users/"+username
		assert os.path.exists(path+"/keystore")

		# Get the description of the user to get the information
		with open(path+"/description", "r") as file:
			content = file.read()

		# Verify if the password match with the hash
		description = json.loads(content)
		ciphered_password = description["password"]
		parsedPassword = base64.b64decode(stringToBytes(ciphered_password))

		try:
			verifyDerivedKey(stringToBytes(password), parsedPassword[16:], parsedPassword[:16])
		except InvalidKey as e:
			print(e)
			return

		# Load the public and private keys
		pubkey = self.loadPublicKey(username)
		privkey = self.loadPrivateKey(username, password)

		# Get the uuid and id of the user
		uuid = base64.b64decode(stringToBytes(description["uuid"]))
		aid = description["id"]

		# Check if smartcard calculated uuid matches with stored uuid

		# Get the citizen card certificate
		# Could not use directly the public key from the CC
		# Because is slightly different from loading the certificate
		# And hash is different from the calculated on the server
		try:
			cert = getAuthCertificate()
		except Exception as e:
			print(e)
			log(logging.ERROR, "Could not get the certificate from the smartcard")
			return False

		authPubKey = dumpPublicKey(loadCertificate(cert).get_pubkey())

		# Calculate the UUID
		uuid = digestSHA256(authPubKey)

		if uuid != base64.b64decode(stringToBytes(description["uuid"])):
			log(logging.ERROR, "Smartcard public key does not match the stored UUID")
			return

		return User(pubkey, privkey, uuid, aid, username)

	def saveUserDescription(self, username, description):
		assert self.checkIfUserExists(username)
		path = "users/"+username
		assert os.path.exists(path)

		with open(path+"/description", "w") as file:
			json.dump(description, file)

		return True

	def loadPrivateKey(self, username, password):
		keyDir = "users/"+username+"/keystore"
		return loadPrivateKeyFromFile(keyDir+"/privKey.key", stringToBytes(password))

	def loadPublicKey(self, username):
		keyDir = "users/"+username+"/keystore"
		return loadPublicKeyFromFile(keyDir+"/pubKey.key")

	def savePrivateKey(self, username, password, key):
		keyDir = "users/"+username+"/keystore"
		saveKeyOnFile(serializePrivateKey(key, stringToBytes(password)), keyDir+"/privKey.key")

	def savePublicKey(self, username, key):
		keyDir = "users/"+username+"/keystore"
		saveKeyOnFile(serializePublicKey(key), keyDir+"/pubKey.key")

	def saveId(self, username, aid):
		assert self.checkIfUserExists(username)
		path = "users/"+username

		# Get the description of the user to get the information
		with open(path+"/description", "r") as file:
			content = file.read()

		# Set the ID of the user
		description = json.loads(content)
		description["id"] = aid

		# Save new ID
		return self.saveUserDescription(username, description)

