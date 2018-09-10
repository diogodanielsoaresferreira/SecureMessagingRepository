#
# Diogo Daniel Soares Ferreira N 76504
# Luis Davide Jesus Leira N 76514
#
# Segurity Messaging Repository System 2017-2018
#
# Cache for the CRL's with time of next update

import requests
from cryptography.hazmat.backends import default_backend
from cryptography import x509
from aux_functions import *
from OpenSSL import crypto
from Crypto.Util import asn1
from log import *
import base64
import logging
import json
import time
import os

class CRLCache:

	def __init__(self):
		self.cache = self.loadCRLDescription()


	# Returns the crls of the certificate
	def getCRLS(self, certificate):
		urls = self.getURLSFromCertificate(certificate)
		crls = []
		for url in urls:
			# Check if CRL exist in memory
			filename = self.searchCRL(url)
			if filename:
				# Check if CRL has not expired
				if self.checkIfValid(url):
					# Load the CRL
					crlTemp = self.loadCRL(filename)
					if crlTemp != None:
						crls += [crlTemp]
					else:
						crl = self.requestCRL(url)
						if crl != None:
							self.addCRLToDescription(crl, url)
							crls += [crl]
				else:
					crl = self.requestCRL(url)
					if crl != None:
						self.updateCRL(crl, url)
						crls += [crl]
			else:
				# Get the CRL from the URL
				crl = self.requestCRL(url)
				if crl != None:
					# Save CRL to description
					self.addCRLToDescription(crl, url)
					crls += [crl]
		return crls

	# Load the CRL description
	def loadCRLDescription(self):
		description = {}

		# Load the description from file, if exists
		path = "CRL/"
		if os.path.exists(path+"description"):
			with open(path+"description", 'rb') as file:
				description = json.loads(bytesToString(file.read()))
				return description

		return description

	# Save the CRL description
	def saveCRLDescription(self):
		path = "CRL/"
		with open(path+"description", 'w') as file:
			file.write(json.dumps(self.cache))
		return True

	# Add CRL to cache
	def addCRLToDescription(self, crl, url):

		crl_object = x509.load_der_x509_crl(crl, default_backend())

		# Index of filename
		if len(self.cache)==0:
			self.cache["global"] = {"index": 1}

		# Create filename and update the index
		filename = str(self.cache["global"]["index"])+".crl"
		self.cache["global"]["index"] += 1

		timestamp = crl_object.next_update.timestamp()

		self.cache[url] = {"filename": filename, "timestamp": timestamp}
		self.saveCRL(crl, filename)
		self.saveCRLDescription()
		return True

	# Update CRL to cache
	def updateCRL(self, crl, url):
		filename = self.cache[url]["filename"]
		crl_object = x509.load_der_x509_crl(crl, default_backend())
		timestamp = crl_object.next_update.timestamp()
		self.cache[url] = {"timestamp": timestamp, "filename": filename}
		self.saveCRL(crl, filename)
		self.saveCRLDescription()
		return True

	# Check if stored CRL is valid
	def checkIfValid(self, url):
		return time.time()<=self.cache[url]["timestamp"]

	# Search CRL from cache
	def searchCRL(self, url):
		if url not in self.cache:
			return

		return self.cache[url]["filename"]

	# Request the CRL via http
	def requestCRL(self, url):
		try:
			r = requests.get(url)
		except Exception as e:
			log(logging.ERROR, "Could not get the CRL via http")
			return
		return r.content

	# Get all the crl url's from the certificate
	def getURLSFromCertificate(self, certificate):
		urls = []

		for i in range(0,certificate.get_extension_count()):
			# Get the crl lists
			if(certificate.get_extension(i).get_short_name()==b'crlDistributionPoints'):
				data=asn1.DerObject()
				data.decode(certificate.get_extension(i).get_data())
				if len(data.payload.split(b'http://'))>1:
					content = data.payload.split(b'http://')[-1]
					urls += ["http://"+bytesToString(content)]

			# Get the delta crl lists
			if(certificate.get_extension(i).get_short_name()==b'freshestCRL'):
				data=asn1.DerObject()
				data.decode(certificate.get_extension(i).get_data())
				if len(data.payload.split(b'http://'))>1:
					content = data.payload.split(b'http://')[-1]
					urls += ["http://"+bytesToString(content)]

		return urls

	# Save CRL in file
	def saveCRL(self, crl, name):
		path = "CRL/"

		if not os.path.exists(path):
			os.mkdir(path)
		
		with open(path+name, 'wb') as file:
			file.write(crl)

		return True
	
	# Load CRL from file
	def loadCRL(self, name):
		path = "CRL/"
		content = ""

		if not os.path.exists(path+name):
			return None
		
		with open(path+name, 'rb') as file:
			content = file.read()

		return content

