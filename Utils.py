import os
import random
import string
import hashlib
import binascii
import unicodedata

from math import *
from datetime import datetime
from OpenSSL import crypto

from Crypto.Cipher import AES
from cryptography import x509
from cryptography.x509.oid import NameOID
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives.serialization import Encoding
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes


manager = ('127.0.0.1', 12345)
repository = ('127.0.0.1', 12356)

class Utils:

	# Verify a certificate and its chain
	def verify(self, certificate, chain):

		# Transform bytes into certificate
		cert = x509.load_der_x509_certificate(certificate, default_backend())
		cert_name = cert.subject.get_attributes_for_oid(NameOID.COMMON_NAME)[0].value+".cer"

		# Get list of trusted certificates by the server        
		trusted_certs = [f for f in os.listdir("server_trusted_certs") if os.path.isfile(os.path.join("server_trusted_certs", f))]
		
		# Get list of trusted certificates by server from the clients 
		trusted_client_certs = [f for f in os.listdir("server_trusted_certs/client_certs") if os.path.isfile(os.path.join("server_trusted_certs/client_certs", f))]

		if cert_name in trusted_certs:
			if cert == x509.load_der_x509_certificate(open(os.path.join("server_trusted_certs", cert_name),"rb").read(),default_backend()):
				
				crl_name = "CRL/cc_ec_cidadao_crl00"+cert_name[-5]+"_crl.crl"
				crl = x509.load_der_x509_crl(open(crl_name, "rb").read(), default_backend())

				if crl.get_revoked_certificate_by_serial_number(cert.serial_number) == None:
					print(" > CERTIFICATE \'{}\' IS TRUSTED".format(cert_name))
					return
				else:
					raise Exception("Certificate {} has expired".format(cert_name))
					
		elif cert_name in trusted_client_certs:
			if cert == x509.load_der_x509_certificate(open(os.path.join("server_trusted_certs/client_certs", cert_name),"rb").read(),default_backend()):
				print(" > CERTIFICATE \'{}\' IS TRUSTED".format(cert_name))
				return

		else:
			print(" > CERTIFICATE \'{}\' NOT PART OF TRUSTED CERTIFICATES".format(cert_name))
				
		# Convert the certificates into a crypto.x509 object
		tmp = []
		for i in chain:
			tmp.append(x509.load_der_x509_certificate(i, default_backend()))

		# Verify the chain
		if len(chain) != 0:
			try:
				self.verify(chain[0],chain[1:])
			except ValueError:
				raise ValueError
			except Exception as e:
				raise e
		else :
			raise ValueError

		# Add new certificate to server_trusted_certs folder
		open("server_trusted_certs/client_certs/"+cert_name, "wb").write(cert.public_bytes(Encoding.DER))


	########### UTILS FUNCTIONS ###########

	# function to encrypt messages using AES 256-bit algorithm
	# size of AES block = 16 bytes (128-bit)
	# https://cryptography.io/en/latest/hazmat/primitives/symmetric-encryption/
	def AES_encrypt(self, key,ctr,msg):
		cipher = Cipher(algorithms.AES(key), modes.CTR(ctr), backend = default_backend())
		encryptor = cipher.encryptor()
		return encryptor.update(bytes(msg,'utf-8')) + encryptor.finalize()

	# function to decipher the messages using AES 256-bit algorithm
	# size of AES block = 16 bytes (128-bit)
	# https://cryptography.io/en/latest/hazmat/primitives/symmetric-encryption/
	def AES_decrypt(self,key,ctr,msg):
		cipher = Cipher(algorithms.AES(key), modes.CTR(ctr), backend = default_backend())
		decryptor = cipher.decryptor()
		return decryptor.update(msg) + decryptor.finalize()

	# function to generate a 2048 bits RSA private key
	# https://cryptography.io/en/latest/hazmat/primitives/asymmetric/rsa/
	def getPrivRSA(self):
		return rsa.generate_private_key(65537,2048,backend = default_backend())

	# function to generate a 2048 bits RSA public key
	# https://cryptography.io/en/latest/hazmat/primitives/asymmetric/rsa/
	def getPubRSA(self, privKey):
		return privKey.public_key()

	# function to create a signature using RSA algorithm
	# https://cryptography.io/en/latest/hazmat/primitives/asymmetric/rsa/
	def sign_msg(self, privKey,data):
		return privKey.sign(
			data,
			padding.PSS(mgf=padding.MGF1(hashes.SHA1()),salt_length=padding.PSS.MAX_LENGTH),
			hashes.SHA1())

	# function to verify the sender's signature
	# https://cryptography.io/en/latest/hazmat/primitives/asymmetric/rsa/
	def verify_sign(self, public_key, signature, msg):
		return public_key.verify(
			signature,
			msg,
			padding.PSS(mgf=padding.MGF1(hashes.SHA1()),salt_length=padding.PSS.MAX_LENGTH),
			hashes.SHA1())

	# https://cryptography.io/en/latest/hazmat/primitives/asymmetric/rsa/?highlight=rsa
	def RSA_encrypt(self, pubKey, message):
		ciphertext = pubKey.encrypt(
			message,
			padding.OAEP(
				mgf=padding.MGF1(algorithm=hashes.SHA256()),
				algorithm=hashes.SHA256(),
				label=None
			)
		)
		return ciphertext


	# https://cryptography.io/en/latest/hazmat/primitives/asymmetric/rsa/?highlight=rsa
	def RSA_decrypt(self, privKey, ciphertext):
		plainText = privKey.decrypt(
			ciphertext,
			padding.OAEP(
				mgf=padding.MGF1(algorithm=hashes.SHA256()),
				algorithm=hashes.SHA256(),
				label=None
			)
		)
		return plainText

	def randomString(self,stringLength=7):
		letters = string.ascii_lowercase
		return ''.join(random.choice(letters) for i in range(stringLength))


	#SOURCE : pastebin.com/n3AshSkh
	def hash1(self,msg):
		hash_object = hashlib.sha256(msg.encode('utf-8'))
		hex_dig = hash_object.hexdigest()
		return hex_dig

	# Generate Hash Cash
	def genCash(self,include,numOfZeros):    
		loop = True
		counter = 0
		random.seed(datetime.now())
		x = str(random.randint(1, 1180591620717411303424))
		while(loop):
			counter = counter + 1
			solution = True
			testHash = self.hash1(include + ":" + x + ":" + str(counter))

			for i in range(0,numOfZeros):
				if ( testHash[i] != "0" ):
					solution = False
					break
			
			if (solution == True):
				loop = False

		toPuzzle = include + ":" + x + ":" + str(counter)
		result = self.hash1(include + ":" + x + ":" + str(counter))

		return toPuzzle, result

		print("")        
		print("Value (ProofOfWork):")
		print("") 
		print(include + ":" + x + ":" + str(counter))
		print("")
		print("") 
		print("Hash (Verification):")
		print("") 
		print(hash1(include + ":" + x + ":" + str(counter)))
		print("")
		print("") 
		print("It took me " + "{:,}".format(counter) + " hashes to figure this out")