#
# Diogo Daniel Soares Ferreira N 76504
# Luis Davide Jesus Leira N 76514
#
# Segurity Messaging Repository System 2017-2018

from security_actions import *

def getServerCertificate():
	with open("keystore/ServerCertificate.crt", "r") as cert_file:
		cert_text = cert_file.read()
		cert = loadCertificate(cert_text)

	return cert

def getServerPrivateKey(password):
	return loadPrivateKeyFromFile("keystore/ServerKeyCiphered.pem", stringToBytes(password))

def getServerPublicKey():
	cert = getServerCertificate()
	return loadPublicKey(dumpPublicKey(cert.get_pubkey()))

def getServerCertificatePath():

	with open("keystore/ServerCA.crt", "r") as cert_file:
		cert_text = cert_file.read()
		CAcert = loadCertificate(cert_text)

	serverCert = getServerCertificate()
	path = getCertificatePath(serverCert, [CAcert], [])

	return path

