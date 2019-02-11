import base64

from Server import *
from DynamicCode import DynamicCode

from cryptography.exceptions import *;
from cryptography.hazmat.primitives.asymmetric import (
	padding, rsa, utils
)
from cryptography.hazmat.primitives.serialization import load_pem_public_key

class Manager(Server):
	"""docstring for Manager"""

	def __init__(self, portNumber):
		super().__init__()
		print(" > LAUNCHING MANAGER SERVER.")
		# Bind socket to port
		self.bind(portNumber)
		# Variable to keep track the amount of auctions created 
		# and to assign them unique serial numbers 
		self.auctionCounter = 0
		
		# asymmetric component
		self.private_key = self.utils.getPrivRSA()
		self.public_key = self.utils.getPubRSA(self.private_key)

		# Writes Manager's public key into a file
		public_key_PEM = self.public_key.public_bytes(
			encoding=serialization.Encoding.PEM,
			format=serialization.PublicFormat.SubjectPublicKeyInfo
		)

		with open("ManagerPubKey.pem", 'wb') as f:
			f.write(public_key_PEM)
			f.close()

	def receive(self):
		super().receive()
		msg = self.message['message']

		print(" > RECEIVED MESSAGE '{}'".format(msg['typeMSG']))

		if msg['typeMSG'] == 'createAuction':
			self.auctionCounter += 1
			self.createAuction(self.message)
		
		elif msg['typeMSG'] == 'decipherBlock':

			print(" > DECIPHERING BLOCK FOR USER ")
			
			# Extract client's signature
			client_signature = base64.b64decode(self.message['signature'])
			# Get client's certificate from message
			client_certificate = base64.b64decode(msg["certificate"])
			certDer = x509.load_der_x509_certificate( client_certificate, default_backend() )
			
			# Extract public key
			pubKey = certDer.public_key()

			chain = []
			for cert in msg['chain']:
				chain.append(base64.b64decode(cert))

			# VERIFY THE VALIDITY OF THE CERTIFICATE		
			try:
				print( " > CHECKING CERTIFICATE CHAIN" )
				self.utils.verify(client_certificate , chain)
				print( " > CERTIFICATE CHAIN IS VALID" )
			except ValueError:
				print( " > CERTIFICATE CHAIN ISN\'T VALID" )
				return
			except Exception as e:
				print( " > ERROR OCCURED WHILE CHECKING CERTIFICATE CHAIN " )
				print( " > ERROR: {}".format(e) )
				return

			# Reconstruct signature
			hasher = hashes.Hash(self.chosen_hash, default_backend())
			hasher.update(msg['typeMSG'].encode())
			hasher.update(str(msg['receipt']).encode())
			hasher.update(msg['certificate'].encode())
			hasher.update(str(msg['chain']).encode())
			hasher.update(msg['key'].encode())
			
			digest = hasher.finalize()

			try:
				print(" > CHECKING CLIENT\'S SIGNATURE ")
				pubKey.verify(client_signature,digest,padding.PKCS1v15(), self.chosen_hash)
				print(" > CLIENT SIGNATURE IS VALID ")
			except InvalidSignature:
				print(" > CLIENT SIGNATURE IS INVALID ")
				return
			except Exception as e:
				print(" ERROR: SIGNATURE IS INVALID")
				print(e.args)
				return None

			##################################### CHECK RECEIPT 
			self.decipherBid(msg)

		elif msg['typeMSG'] == 'terminateAuction':
			self.terminateAuction(self.message)

		elif msg['typeMSG'] == 'makeBid':
			
			repo_signature = base64.b64decode(self.message['signature_repo'])

			with open('RepositoryPubKey.pem', 'rb') as publicfile:
				pubkeydata = publicfile.read()

			rep_pub_key = load_pem_public_key(pubkeydata,default_backend())

			hasher = hashes.Hash(self.chosen_hash, default_backend())
			hasher.update(str(self.message['message']).encode())
			hasher.update(self.message['signature'].encode())
			hasher.update(str(self.message['auctionInfo']).encode())
			digest = hasher.finalize()

			# Check to see if repository signature is valid
			print(' > CHECKING REPOSITORY SIGNATURE')
			try:
				self.utils.verify_sign(rep_pub_key,repo_signature,digest)
				print(' > REPOSITORY SIGNATURE IS VALID')
			except ValueError:
				print(' > REPOSITORY SIGNATURE IS INVALID')
				self.bidMessage({ 'validBid' : False, 'Error' : 'Repository Signature isn\'t valid'})
			except Exception:
				print(" > ERROR OCCURED WHILE TRYING TO VALIDATE REPOSITORY SIGNATURE \n > ERROR: {}".format(e))
				self.bidMessage({ 'validBid' : False, 'Error' : 'Error occured while trying to validate bid'})

			# If certificate is hidden check the signature first 
			if self.message['auctionInfo']['AuctionType'] == 0:

				print(' > CHECKING CLIENT SIGNATURE ')
				try:
					self.validateClientSig(self.message['message'],self.message['signature'])
					print(' > CLIENT SIGNATURE IS VALID')
				except ValueError:
					print(' > CLIENT SIGNATURE IS INVALID')
					self.bidMessage({ 'validBid' : False, 'Error' : 'Client Signature isn\'t valid'})
				except Exception:
					print(" > ERROR OCCURED WHILE TRYING TO VALIDATE CLIENT SIGNATURE \n > ERROR: {}".format(e))
					self.bidMessage({ 'validBid' : False, 'Error' : 'Error occured while trying to validate bid'})

			# Check to see if bid is valid 
			print(' > CHECKING BID ')
			try: 
				self.validateBid(self.message['message'],self.message['auctionInfo']);
				print(' > BID IS VALID')
			except ValueError as e:
				print(' > BID ISN\'T VALID : ', e)
				self.bidMessage({ 'validBid' : False, 'Error' : e.args[0]})
			except Exception as e:
				print(" > ERROR OCCURED WHILE TRYING TO VALIDATE BID \n > ERROR: {}".format(e))
				self.bidMessage({ 'validBid' : False, 'Error' : 'Error occured while trying to validate bid'})

	def createAuction(self, message):
		msg = message['message']
		
		# Extract client's signature
		client_signature = base64.b64decode(message['signature'])
		# Get client's certificate from message
		client_certificate = base64.b64decode( msg["certificate"])
		certDer = x509.load_der_x509_certificate( client_certificate, default_backend() )
		
		# Extract public key
		pubKey = certDer.public_key()
		
		chain = []
		for cert in msg['chain']:
			chain.append(base64.b64decode(cert))

		# VERIFY THE VALIDITY OF THE CERTIFICATE		
		try:
			self.utils.verify(client_certificate , chain)
			print(" > CERTIFICATE CHAIN IS VALID")
		except ValueError:
			print( " > CERTIFICATE CHAIN ISN\'T VALID")
			return 
		except Exception as e:
			print( " > ERROR OCCURED WHILE CHECKING CERTIFICATE CHAIN ")
			print( " > ERROR: {}".format(e))
			return		

		#https://cryptography.io/en/latest/hazmat/primitives/asymmetric/rsa/?highlight=signature
		hasher = hashes.Hash(self.chosen_hash, default_backend())
		hasher.update(msg['typeMSG'].encode())
		hasher.update(msg['auctionName'].encode())
		hasher.update(str(msg['auctionType']).encode())
		hasher.update(str(msg['timeLimit']).encode())
		hasher.update(msg['description'].encode())
		hasher.update(msg['dynamic_code'].encode()),
		hasher.update(msg['certificate'].encode())
		hasher.update(str(msg['chain']).encode())
		digest = hasher.finalize()

		#Verify Signature 
		try:
			pubKey.verify(client_signature,digest,padding.PKCS1v15(), self.chosen_hash)
			print(' > CLIENT SIGNATURE IS VALID')
		except InvalidSignature:
			print(' > CLIENT SIGNATURE IS INVALID')
			return
		except Exception as e:
			print(" > ERROR OCCURED WHILE CHECKING SIGNATURE")
			print(" > ERROR: {}".format(e))
			return 

		# Create Message
		newMSG = {
			'typeMSG' : 'createAuction', 
			'serialNb' : self.auctionCounter, 
			'auctionName' : msg['auctionName'], 
			'auctionType' : msg['auctionType'],
			'timeLimit' : msg['timeLimit'],
			'description' : msg['description'],
			'dynamic_code' : msg['dynamic_code'],
			'certificate' : msg['certificate']
			}

		# Create Signature
		hasher = hashes.Hash(self.chosen_hash, default_backend())
		hasher.update(newMSG['typeMSG'].encode())
		hasher.update(str(newMSG['serialNb']).encode())
		hasher.update(newMSG['auctionName'].encode())
		hasher.update(str(newMSG['auctionType']).encode())
		hasher.update(str(newMSG['timeLimit']).encode())
		hasher.update(newMSG['description'].encode())
		hasher.update(newMSG['dynamic_code'].encode())
		hasher.update(newMSG['certificate'].encode())
		digest = hasher.finalize()

		# Sign Message
		signature = self.utils.sign_msg(self.private_key, digest)
		
		print(" > SENDING MESSAGE TO REPOSITORY")
		# Send Message 
		self.send(json.dumps({
			'message' : newMSG,
			'signature' : base64.b64encode(signature).decode('utf-8')
		}),repository)

	def terminateAuction(self,message):
		msg = message['message']

		# Extract client's signature from message received
		client_signature = base64.b64decode(message['signature'])
		# Extract client's certificate from message received
		client_certificate = base64.b64decode(msg["certificate"])
		# Load certificate from bytes to X509.Certificate
		certDer = x509.load_der_x509_certificate( client_certificate, default_backend() )
		# Extract public key
		pubKey = certDer.public_key()

		# Verify the certificate chain	
		chain = []
		for cert in msg['chain']:
			chain.append(base64.b64decode(cert))

		try:
			self.utils.verify(client_certificate , chain)
			print( " > CERTIFICATE CHAIN IS VALID" )
		except ValueError:
			print( " > CERTIFICATE CHAIN ISN\'T VALID" )
			return
		except Exception as e:
			print( " > ERROR OCCURED WHILE CHECKING CERTIFICATE CHAIN " )
			print( " > ERROR: {}".format(e) )
			return		

		# Verify the signature
		hasher = hashes.Hash(self.chosen_hash, default_backend())
		hasher.update(msg['typeMSG'].encode())
		hasher.update(str(msg['serialNb']).encode())
		hasher.update(msg['certificate'].encode())
		hasher.update(str(msg['chain']).encode())
		digest = hasher.finalize()

		try:
			pubKey.verify(client_signature,digest,padding.PKCS1v15(), self.chosen_hash)
			print(' > SIGNATURE IS VALID')
		except InvalidSignature:
			print(' > SIGNATURE IS INVALID')
			return
		except Exception as e:
			print(" ERROR: SIGNATURE IS INVALID")
			print(e.args)
			return

		# Make message to send to repository
		newMSG = {
			'typeMSG' : msg['typeMSG'],
			'serialNb' : msg['serialNb']
		}
		
		# Get message's signature 
		hasher = hashes.Hash(self.chosen_hash, default_backend())
		hasher.update(newMSG['typeMSG'].encode())
		hasher.update(str(newMSG['serialNb']).encode())
		digest = hasher.finalize()

		signature = self.utils.sign_msg(self.private_key, digest)

		# Send message to repository
		self.send(json.dumps({
			'message': newMSG,
			'signature': base64.b64encode(signature).decode('utf-8')
		}), repository)

	def validateClientSig(self, msg, signature):

		key = base64.b64decode(msg['key'])
		
		#Decipher AES key
		key = self.utils.RSA_decrypt(self.private_key, key)		
		key = json.loads(key)

		# Decipher certificate
		client_signature = base64.b64decode(signature)	
		client_certificate = self.utils.AES_decrypt(
			base64.b64decode(key['identity']),
			base64.b64decode(key['iv']),
			base64.b64decode(msg['certificate'])
		)

		client_certificate = base64.b64decode(client_certificate)
		certDer = x509.load_der_x509_certificate( client_certificate, default_backend() )
		pubKey = certDer.public_key()

		# Create signature
		hasher = hashes.Hash(self.chosen_hash, default_backend())
		hasher.update(msg['typeMSG'].encode())
		hasher.update(str(msg['serialNb']).encode())
		hasher.update(str(msg['bidAmount']).encode())
		hasher.update(msg['certificate'].encode())
		hasher.update(str(msg['chain']).encode())
		hasher.update(msg['key'].encode())
		digest = hasher.finalize()
			
		# Verify client's signature 
		try:
			pubKey.verify(client_signature,digest,padding.PKCS1v15(), self.chosen_hash)
		except InvalidSignature:
			raise ValueError
		except Exception:
			raise(e)

	def validateBid(self, msg, auctionInfo):
		if auctionInfo['AuctionType'] == 0:
			if auctionInfo['biggestBid'] < msg['bidAmount']:
				if DynamicCode().run_dynamic_code(auctionInfo['dynamic_code'],msg['bidAmount'],auctionInfo['biggestBid']):
					message = { 'validBid' : True }
				else:
					raise ValueError("Bid doesn't respect dynamic code")
			else: 
				raise ValueError('Bid not high enough')
		else: 
			if DynamicCode().run_dynamic_code(auctionInfo['dynamic_code'],0,0):
					message = { 'validBid' : True }
			else:
				raise ValueError("Bid doesn't respect dynamic code")

		self.bidMessage(message)
	
	def bidMessage(self,msg):

		hasher = hashes.Hash(self.chosen_hash, default_backend())
		hasher.update(str(self.message['message']).encode())
		hasher.update(self.message['signature'].encode())
		hasher.update(str(msg).encode())
		digest = hasher.finalize()

		signature = self.utils.sign_msg(self.private_key, digest) 

		self.send(json.dumps({
			'message' : self.message['message'],
			'signature' : self.message['signature'],
			'bidValidity' : msg,
			'signature_man' : base64.b64encode(signature).decode('utf-8')
		}),self.client)

	def decipherBid(self, message):

			# Extract receipt from message
			# receipt = message['']
			# Verify receipt
			# Save address of client for latter use 
			address = self.client
			# Extract key from message
			key = base64.b64decode(message['key'])	

			#Ask for block
			message = { 
				'typeMSG' : 'retrieveBlock',
				'auctionNumber' : message['receipt']['block']['serialNb'],
				'blockNumber': message['receipt']['block']['index']
			}	

			# Generate the repository signature
			hasher = hashes.Hash(self.chosen_hash, default_backend())
			hasher.update(message['typeMSG'].encode())
			hasher.update(str(message['auctionNumber']).encode())
			hasher.update(str(message['blockNumber']).encode())
			digest = hasher.finalize()

			signature = self.utils.sign_msg(self.private_key, digest)

			# Return message and inform client about the auction type
			self.send(json.dumps({
				'message' : message,
				'signature' : base64.b64encode(signature).decode('utf-8')
			}),repository)

			# Listen for response from repository
			super().receive()
			msg = self.message['message']
			# Extract repository's signature from the message
			repo_signature = base64.b64decode(self.message['signature'])

			with open('RepositoryPubKey.pem', 'rb') as publicfile:
				pubkeydata = publicfile.read()

			repo_pub_key = load_pem_public_key(pubkeydata,default_backend())

			# Reconstruct repository signature
			hasher = hashes.Hash(self.chosen_hash, default_backend())
			hasher.update(str(msg['block']).encode())
			
			digest = hasher.finalize()

			# Verify the repository signature 
			print(" > CHECKING REPOSITORY SIGNATURE ")
			try:
				self.utils.verify_sign(repo_pub_key,repo_signature,digest)
				print(" > REPOSITORY SIGNATURE IS VALID ")
			except InvalidSignature:
				print(" > REPOSITORY SIGNATURE IS INVALID ")
				return
			except Exception as e:
				print(' > ERROR OCCURED WHILE TRYING TO VALIDATE REPOSITORY SIGNATURE \n > ERROR: {}',e)
				print(e.args)
				return None

			# Decipher AES key
			key = self.utils.RSA_decrypt(self.private_key, key)		
			key = json.loads(key)

			if key['field'] == 'certificate':
				print(" > DECIPHERING CERTIFICATE IN BLOCK")
				deciphered_value = self.utils.AES_decrypt(
					base64.b64decode(key['identity']),
					base64.b64decode(key['iv']),
					base64.b64decode(msg['block']['author'])
				)

				deciphered_value = base64.b64decode(deciphered_value)

				deciphered_block = {
					'index' : msg['block']['index'],
					'author' : base64.b64encode(deciphered_value).decode('utf-8'),
					'bid' : msg['block']['bid'],
					'serialNb' : msg['block']['serialNb'],
				}

			elif key['field'] == 'amount':
				print(" > DECIPHERING BID AMOUNT IN BLOCK")
				deciphered_value = self.utils.AES_decrypt(
					base64.b64decode(key['identity']),
					base64.b64decode(key['iv']),
					base64.b64decode(msg['block']['bid'])
				)

				deciphered_block = {
					'index' : msg['block']['index'],
					'author' : msg['block']['author'],
					'bid' : str(deciphered_value),
					'serialNb' : msg['block']['serialNb'],
				}

			# Construct message to send to repository
			message = {
				'typeMSG' : 'decipherBlock',
				'block' : deciphered_block
			}
			# Construct signature
			hasher = hashes.Hash(self.chosen_hash, default_backend())
			hasher.update(message['typeMSG'].encode())
			hasher.update(str(message['block']).encode())
			
			digest = hasher.finalize()

			signature = self.utils.sign_msg(self.private_key, digest)

			# Send message to repository
			self.send(json.dumps({
				'message' : message,
				'signature' : base64.b64encode(signature).decode('utf-8')
			}),repository)

			# Construct message to send to client
			message = {
				'answer' : 'Value deciphered'
			}
			# Construct signature
			hasher = hashes.Hash(self.chosen_hash, default_backend())
			hasher.update(message['answer'].encode())
			
			digest = hasher.finalize()

			signature = self.utils.sign_msg(self.private_key, digest)

			# Send message to repository
			self.send(json.dumps({
				'message' : message,
				'signature' : base64.b64encode(signature).decode('utf-8')
			}),address)			


if __name__ == "__main__":
	server = Manager(12345)
	while True:
		print('\n > MANAGER SERVER WAITING FOR NEW MESSAGE.')
		server.receive()	
	