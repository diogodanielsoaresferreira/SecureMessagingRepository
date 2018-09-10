#
#
# Diogo Daniel Soares Ferreira N 76504
# Luis Davide Jesus Leira N 76514
#
# Segurity Messaging Repository System 2017-2018

import base64
import os
from aux_functions import *
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.asymmetric import dh, ec
from cryptography.hazmat.primitives.ciphers import (
	Cipher, algorithms, modes
)
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.serialization import *
from cryptography.x509.oid import ExtensionOID
from cryptography import x509
from Crypto.Util import asn1
from OpenSSL import crypto
from CRLCache import CRLCache
import jks


# Generate 32 bit random number, converted to base64
# Padding is added
def generateNonce():
	rand = os.urandom(32)
	return rand

# Cipher message with aes in ctr mode, and return also key and iv
def cipherMessage(message):
	key = os.urandom(32)
	iv = os.urandom(16)
	cipher = Cipher(algorithms.AES(key), modes.CTR(iv), backend=default_backend())
	encryptor = cipher.encryptor()
	ct = encryptor.update(message)+encryptor.finalize()
	return key, iv, ct

# Decipher messages with AES in ctr mode, given the key and the iv
def decipherMessage(key, iv, message):
	cipher = Cipher(algorithms.AES(key), modes.CTR(iv), backend=default_backend())
	decryptor = cipher.decryptor()
	return decryptor.update(message)+decryptor.finalize()

# Cipher message with integrity check
def cipherMessageWithIntegrityCheck(message, key=None):
	if key is None:
		key = os.urandom(32)
	iv = os.urandom(16)
	cipher = AESGCM(key)
	return key, iv, cipher.encrypt(iv, message, None)

# Decipher message with integrity check
def decipherMessageWithIntegrityCheck(key, iv, message):
	cipher = AESGCM(key)
	return cipher.decrypt(iv, message, None)

# Cipher with RSA assymetric cipher
def cipherAssymetricMessage(key, message):
	msg = key.encrypt(
		message,
		padding.OAEP(
			mgf=padding.MGF1(algorithm=hashes.SHA256()),
			algorithm=hashes.SHA256(),
			label=None
			)
	)
	return msg
	
# Decipher with RSA assymetric cipher
def decipherAssymetricMessage(key, message):
	msg = key.decrypt(
		message,
		padding.OAEP(
			mgf=padding.MGF1(algorithm=hashes.SHA256()),
			algorithm=hashes.SHA256(),
			label=None
		)
	)
	return msg

# Sign a message
def signMessage(key, message):
	return key.sign(
		message,
		padding.PSS(
			mgf=padding.MGF1(hashes.SHA256()),
			salt_length=padding.PSS.MAX_LENGTH
		),
		hashes.SHA256()
	)

# Verify the signature of message
def verifySigning(key, message, signature):
	key.verify(
		signature,
		message,
		padding.PSS(
			mgf = padding.MGF1(hashes.SHA256()),
			salt_length=padding.PSS.MAX_LENGTH
		),
		hashes.SHA256()
	)

# Generate pair of keys
def generateKeys():
	key = rsa.generate_private_key(
		 public_exponent=65537,
		 key_size=2048,
		 backend=default_backend()
	)
	return key, key.public_key()


# Key derivation
def deriveKey(key, iv=None):
	if iv==None:
		iv = os.urandom(16)
	kdf = PBKDF2HMAC(
	    algorithm=hashes.SHA256(),
	    length=32,
	    salt=iv,
	    iterations=100000,
	    backend=default_backend()
	)
	key = kdf.derive(key)
	return key, iv

# Verify if the key matches the derived key
def verifyDerivedKey(key, derived, iv):
	kdf = PBKDF2HMAC(
	    algorithm=hashes.SHA256(),
	    length=32,
	    salt=iv,
	    iterations=100000,
	    backend=default_backend()
	)
	kdf.verify(key, derived)

# Serialize public key
def serializePublicKey(key):
	return key.public_bytes(
		encoding=serialization.Encoding.PEM,
		format=serialization.PublicFormat.SubjectPublicKeyInfo
	)

# Serialize private key
def serializePrivateKey(key, password=None):
	if password==None:
		return key.private_bytes(
			encoding=serialization.Encoding.PEM,
			format=serialization.PrivateFormat.TraditionalOpenSSL,
			encryption_algorithm=serialization.NoEncryption()
		)
	else:
		return key.private_bytes(
			encoding=serialization.Encoding.PEM,
			format=serialization.PrivateFormat.TraditionalOpenSSL,
			encryption_algorithm=serialization.BestAvailableEncryption(password)
		)

# Load private key from file
def loadPrivateKeyFromFile(path, password=None):
	privKey = None
	with open(path, "rb") as key_file:
		privKey = serialization.load_pem_private_key(
		key_file.read(),
		password=password,
		backend=default_backend()
	)
	return privKey


# Load public key from file
def loadPublicKeyFromFile(path):
	pubKey = None
	with open(path, "rb") as key_file:
		pubKey = serialization.load_pem_public_key(
			key_file.read(),
			backend=default_backend()
		)
	return pubKey

# Load private key from argument
def loadPrivateKey(key, password=None):
	privKey = serialization.load_pem_private_key(
		key,
		password=password,
		backend=default_backend()
	)
	return privKey


# Load public key from argument
def loadPublicKey(key):
	pubKey = serialization.load_pem_public_key(
		key,
		backend=default_backend()
	)
	return pubKey

# Dump public key from argument
def dumpPublicKey(key):
	return crypto.dump_publickey(crypto.FILETYPE_PEM, key)

# Save key on file
def saveKeyOnFile(key, path):
	if os.path.exists(path):
		mode = "w+"
	with open(path, "wb") as key_file:
		key_file.write(key)
	return True

# Digest with SHA-256
def digestSHA256(text):
	digest = hashes.Hash(
		hashes.SHA256(),
		backend=default_backend()
	)
	digest.update(text)
	return digest.finalize()

# Load certificate
def loadCertificate(certificate):
	return crypto.load_certificate(crypto.FILETYPE_PEM, certificate)

# Dump certificate
def dumpCertificate(certificate):
	return crypto.dump_certificate(crypto.FILETYPE_PEM, certificate)

# Load public key (with OpenSSL)
def loadPubKey(key):
	return crypto.load_publickey(crypto.FILETYPE_PEM, key)

# Verify CC signature
def verifyCCSignature(pubkey, signature, data, digest):
	x509 = crypto.X509()
	x509.set_pubkey(pubkey)

	return crypto.verify(x509, signature, data, digest)

# Verify the signature of a certificate by a CA
def verifyCertificateSignature(certificate, ca_certificate):
	
	# Get the signature algorithm
	algorithm=certificate.get_signature_algorithm()
	cert_asn1=crypto.dump_certificate(crypto.FILETYPE_ASN1, certificate)

	# Decode the certificate
	der=asn1.DerSequence()
	der.decode(cert_asn1)

	# Der is [certificate, signature algorithm, signature]
	der_cert=der[0]
	der_algo=der[1]
	der_sig=der[2]

	# Decode signature
	der_sigTemp=asn1.DerObject()
	der_sigTemp.decode(der_sig)

	# Get the signature
	sig=der_sigTemp.payload[1:]
 
	# Verify the certificate
	try:
		crypto.verify(ca_certificate, sig, der_cert, bytesToString(algorithm))
		return True
	except crypto.Error as e:
		return False

# Verifies if the Crl signature is valid
def verifyCrlSignature(crl, certificate):

	crl = x509.load_der_x509_crl(crl, default_backend())
	pubkey = certificate.get_pubkey().to_cryptography_key()
	return crl.is_signature_valid(pubkey)


# Check if certificate is revoked
def checkCertificateRevoked(certificate, parent_cert):

	crlCache = CRLCache()

	# Get all crl's from certificate
	crls = crlCache.getCRLS(certificate)

	# Check if certificate serial number matches with any revoked certificate serial number
	for crl in crls:
		
		# Check if the CRL can be validated
		if not verifyCrlSignature(crl, parent_cert):
			return False

		crl_object = crypto.load_crl(crypto.FILETYPE_ASN1, crl)
		revoked_objects = crl_object.get_revoked()
		if revoked_objects != None:
			for rvk in revoked_objects:
				if bytesToString(rvk.get_serial())==certificate.get_serial_number():
					return True

	return False


# Create the certificate chain
def getCertificatePath(certificate, trusted_anchors, intermediate_certificates, path={}):

	issuer = certificate.get_issuer().hash()
	subject = certificate.get_subject().hash()
				 
	for c in intermediate_certificates:
		parent_issuer = c.get_issuer().hash()
		parent_subject = c.get_subject().hash()
		
		# Check if the issuer of the certificate is the subject of the parent
		if(subject != parent_subject and issuer == parent_subject):
			path[subject] = c
			path = getCertificatePath(c, trusted_anchors, intermediate_certificates, path)
			return path

	# With the middleware v1.61 of CC there are no trusted anchors in the card
	for trusted in trusted_anchors:
		parent_issuer = trusted.get_issuer().hash()
		parent_subject = trusted.get_subject().hash()

		if(parent_subject == issuer):
			path[subject] = trusted
			return path


	return None

# Validates the certificate chain
def validateCertificateChain(certificate, cert_chain):
	validated = False

	if cert_chain == None:
		return False

	trusted_root_certificates, trusted_intermediate_certificates = getTrustedCertificates()
	trusted_root_cert_bytes = [dumpCertificate(cert_bytes) for cert_bytes in trusted_root_certificates]
	trusted_int_cert_bytes = [dumpCertificate(cert_bytes) for cert_bytes in trusted_intermediate_certificates]


	current_cert = certificate

	# Check if certificate can be used to make digital signatures and to establish key agreements
	if not checkCertificateDigitalSignature(certificate) or not checkCertificateKeyAgreement(certificate):
		return False

	while not validated:
		# Check if it has expired
		if(current_cert.has_expired()):
			return False

		# Get the parent CA
		if(current_cert.get_subject().hash()==current_cert.get_issuer().hash()):
			validated = True
			parent_cert = current_cert

			# Check if root certificate is trusted
			if dumpCertificate(parent_cert) not in trusted_root_cert_bytes:
				return False

		else:
			parent_cert = cert_chain[current_cert.get_subject().hash()]
		
		# Check if CA can sign keys and CRLs
		if not checkCertificateSign(parent_cert) or not checkCertificateCRLSign(parent_cert):
			return False

		# Check if certificate is correctly signed by a CA
		verify = verifyCertificateSignature(current_cert, parent_cert)
		if not verify:
			return False

		# Check if certificate has not been revoked
		revoked = checkCertificateRevoked(current_cert, parent_cert)
		if(revoked):
			return False


		current_cert = parent_cert
		
	return True
	
# Get all trusted certificates
def getTrustedCertificates():
	# Get CC certificates from keystore

	keystore = jks.KeyStore.load('trusted_certs/CC_KS', 'password')
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

	# Get server CA certificate from file
	with open("trusted_certs/ServerCA.crt", "r") as cert_file:
		cert_text = cert_file.read()
		cert = crypto.load_certificate(crypto.FILETYPE_PEM, cert_text)

		if cert.get_subject().CN==cert.get_issuer().CN:
			trusted_anchors += [cert]
		else:
			intermediate_certificates += [cert]

	return trusted_anchors, intermediate_certificates

# Checks if certificate can be used for digital signature
def checkCertificateDigitalSignature(certificate):
	cert = certificate.to_cryptography()
	keyusage = cert.extensions.get_extension_for_oid(ExtensionOID.KEY_USAGE)
	return keyusage.value.digital_signature


# Checks if certificate can be used for key agreement
def checkCertificateKeyAgreement(certificate):
	cert = certificate.to_cryptography()
	keyusage = cert.extensions.get_extension_for_oid(ExtensionOID.KEY_USAGE)
	return keyusage.value.key_agreement

# Checks if certificate can sign keys
def checkCertificateSign(certificate):
	cert = certificate.to_cryptography()
	keyusage = cert.extensions.get_extension_for_oid(ExtensionOID.KEY_USAGE)
	return keyusage.value.key_cert_sign

# Checks if certificate can be used for signing crl's
def checkCertificateCRLSign(certificate):
	cert = certificate.to_cryptography()
	keyusage = cert.extensions.get_extension_for_oid(ExtensionOID.KEY_USAGE)
	return keyusage.value.crl_sign

# Generates the keys for the elliptic curve diffie-hellman
def ECDHgenerate():
	return ec.generate_private_key(
		ec.SECP256K1(), default_backend()
	)

# Calculates the session key with the elliptic curve diffie-hellman algorithm
def ECDHcalculate(private_key_pem, public_key_pem):
	private_key = load_pem_private_key(private_key_pem, password=None, backend=default_backend())
	peer_public_key = load_pem_public_key(public_key_pem, backend=default_backend())
	
	return private_key.exchange(ec.ECDH(), peer_public_key)
