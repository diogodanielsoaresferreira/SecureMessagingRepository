#
#
# Diogo Daniel Soares Ferreira N 76504
# Luis Davide Jesus Leira N 76514
#
# Security Messaging Repository System 2017-2018
#
# Cache for public keys for clients
# Implemented with LRU policy
#
# Public key must be stored in string format

MAX_LENGTH_PUBLIC_KEY_CACHE = 32

class PublicKeyCache:
	def __init__(self):
		self.cache = []

	def add(self, aid, publicKey):
		# If key already exists, update it
		if(self.getIndex(aid) != None):
			return self.updatePublicKey(aid, publicKey)

		# Else, save public key on cache
		self.cache.append({aid: publicKey})

		# If size is above the maximum size, delete the key that was accessed more time ago
		if len(self.cache) >= MAX_LENGTH_PUBLIC_KEY_CACHE:
			self.cache = self.cache[1:]

	# Search public key by id
	def search(self, aid):
		idx = self.getIndex(aid)
		# If id exists, put it last on the list
		if(idx != None):
			value = self.cache[idx][aid]
			self.updatePublicKey(aid, value)
			return value
	
	# Get index of id, if exists
	def getIndex(self, aid):
		for idx, elemId in enumerate(self.cache):
			if aid in elemId:
				return idx

	# Update public key and change its location on cache
	def updatePublicKey(self, aid, publicKey):
		idx = self.getIndex(aid)
		self.cache = self.cache[:idx]+self.cache[idx+1:]+[self.cache[idx]]
