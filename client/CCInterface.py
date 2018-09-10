#
# Diogo Daniel Soares Ferreira N 76504
# Luis Davide Jesus Leira N 76514
#
# Segurity Messaging Repository System 2017-2018

import pkcs11
import logging
from log import *
from pkcs11.constants import *
from security_actions import *
import jks
from OpenSSL import crypto

keystore = jks.KeyStore.load('trusted_certs/CC_KS', 'password')

# Get token of portuguese citizen card
def getCCToken():

	try:
		lib = pkcs11.lib('/usr/local/lib/libpteidpkcs11.so')
		token = None
		slots = lib.get_slots()

		if len(slots)==0:
			log(logging.ERROR, "Could not find Portuguese Citizen Card")
			return

		for slot in slots:
			token = slot.get_token()
			break

	except Exception as e:
		print(e)
		log(logging.ERROR, "Could not find Portuguese Citizen Card")
		return

	return token


# Returns the public key for authentication of the card
def getAuthPublicKey():
	bytesPubKey = None
	token = getCCToken()

	with token.open() as session:

		pubKeys = session.get_objects({Attribute.CLASS: ObjectClass.PUBLIC_KEY, Attribute.LABEL: 'CITIZEN AUTHENTICATION CERTIFICATE'})
		pubKey = None

		for key in pubKeys:
			pubKey = key
			break

		pubKeys = None

		if(pubKey is None):
			log(logging.ERROR, "Could not find authentication key in the Portuguese Citizen Card")
			return None

		bytesPubKey = pubKey[Attribute.VALUE]

	return bytesPubKey


# Get all certificates from the card
def getAllCertificates():
	certs = []
	token = getCCToken()

	with token.open() as session:

		for cert in session.get_objects({
			Attribute.CLASS: ObjectClass.CERTIFICATE,
			}):

			t = crypto.load_certificate(crypto.FILETYPE_ASN1, cert[Attribute.VALUE])
			
			certs += [cert]

	return certs

# Sign a message
def sign(data):
	token = getCCToken()

	with token.open() as session:

		privKeys = session.get_objects({Attribute.CLASS: ObjectClass.PRIVATE_KEY, Attribute.LABEL: 'CITIZEN AUTHENTICATION KEY'})
		privKey = None

		for key in privKeys:
			privKey = key
			break

		privKeys = None

		if(privKey is None):
			log(logging.ERROR, "Could not find authentication key in the Portuguese Citizen Card")
			return
					
		# Signature
		signature = privKey.sign(data, mechanism=pkcs11.Mechanism.SHA256_RSA_PKCS)

	return signature

# Get certificate for auth key
def getAuthCertificate():
	token = getCCToken()

	with token.open() as session:

		for cert in session.get_objects({Attribute.CLASS: ObjectClass.CERTIFICATE, Attribute.LABEL: 'CITIZEN AUTHENTICATION CERTIFICATE'}):
			
			# Convert from DER-encoded value to OpenSSL object
			cert = crypto.load_certificate(
				crypto.FILETYPE_ASN1,
				cert[Attribute.VALUE],
			)
						
			# Convert to PEM format
			cert = crypto.dump_certificate(
				crypto.FILETYPE_PEM,
				cert
			)

			return cert

# Get certificates from card
def getCertificates():
	token = getCCToken()

	with token.open() as session:

		root = []
		intermediate = []

		for cert in session.get_objects({Attribute.CLASS: ObjectClass.CERTIFICATE}):
			
			# Convert from DER-encoded value to OpenSSL object
			cert = crypto.load_certificate(
				crypto.FILETYPE_ASN1,
				cert[Attribute.VALUE],
			)

			subject = cert.get_subject().CN
			issuer = cert.get_issuer().CN

			# Middleware 1.61 does not have root certs
			if(subject==issuer):	
				root += [cert]
			else:
				intermediate += [cert]

		return root, intermediate

# Get certificates from keystore
def get_cert_keystore():
	trusted_anchors = []
	intermediate_certificates = []

	for alias, certificate in keystore.certs.items():

		cert = crypto.load_certificate(
			crypto.FILETYPE_ASN1,
				certificate.cert,
			)

		subject = cert.get_subject().CN
		issuer = cert.get_issuer().CN
		

		if(subject==issuer):
			trusted_anchors += [cert]
		else:
			intermediate_certificates += [cert]

	return trusted_anchors, intermediate_certificates

