import time
import base64
import threading

from Server import *	
from Block import Block

from cryptography.exceptions import *
from cryptography.hazmat.primitives import hashes  
from cryptography.hazmat.backends import default_backend  
from cryptography.hazmat.primitives.asymmetric import (
	padding, rsa, utils
)
from cryptography.hazmat.primitives.serialization import load_pem_public_key

class Repository(Server):
	"""docstring for Repository"""

	def __init__(self, portNumber):
		super().__init__()
		print(" > LAUNCHING REPOSITORY SERVER.")
		# Bind socket to port
		self.bind(portNumber)
		# List of open auctions
		self.opAuctLst = []
		# List of closed auctions
		self.clAuctLst = []
		# Lock used by threads to make sure there 
		# isn't simultaneous access to shared resources 
		self.lock = threading.RLock()

		# asymmetric component
		self.private_key = self.utils.getPrivRSA()
		self.public_key = self.utils.getPubRSA(self.private_key)

		# Writes Repository's public key into a file
		public_key_PEM = self.public_key.public_bytes(
			encoding = serialization.Encoding.PEM,
			format = serialization.PublicFormat.SubjectPublicKeyInfo
		)		
		
		with open("RepositoryPubKey.pem", 'wb') as f:
			f.write(public_key_PEM)
			f.close()

	def receive(self):
		super().receive()

		typeMSG = self.message['message']['typeMSG']

		print(" > RECEIVED MESSAGE '{}'".format(typeMSG))

		if typeMSG == 'getAuctionType':
			msg = self.message['message']

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
				self.utils.verify(client_certificate , chain)
				print( " > CERTIFICATE CHAIN IS VALID" )
			except ValueError:
				print( " > CERTIFICATE CHAIN ISN\'T VALID" )
				return
			except Exception as e:
				print( " > ERROR OCCURED WHILE CHECKING CERTIFICATE CHAIN " )
				print( " > ERROR: {}".format(e) )
				return		

			#https://cryptography.io/en/latest/hazmat/primitives/asymmetric/rsa/?highlight=signature
			hasher = hashes.Hash(self.chosen_hash, default_backend())
			hasher.update(msg['typeMSG'].encode())
			hasher.update(msg['option'].encode())
			hasher.update(str(msg['serialNb']).encode())
			hasher.update(msg['certificate'].encode())
			hasher.update(str(msg['chain']).encode())
			digest = hasher.finalize()

			#Verify Signature 
			try:
				pubKey.verify(client_signature,digest,padding.PKCS1v15(), self.chosen_hash)
				print(' > SIGNATURE IS VALID')
			except InvalidSignature:
				print(' > SIGNATURE IS INVALID')
			except Exception as e:
				print(" ERROR: SIGNATURE IS INVALID")
				print(e.args)
				return None

			# If the 
			if msg['option'] == 'make_bid':
				# Get the type of the auction
				auctionType = self.returnTypeOfAuction(msg['serialNb'],self.opAuctLst)
					
				# Generate string to compute
				stringToCompute = self.utils.randomString(8)
				print(" > STRING GENERATED : ",stringToCompute)
				# Define number of zeros
				numOfZeros = 3
				
				# Construct answer to send to client
				message = { 
					'typeMSG' : 'answer', 
					'auctionType' : auctionType, 
					'cryptoPuzzle': stringToCompute,
					'numOfZeros': numOfZeros
				}	
			
				# Generate the repository signature
				hasher = hashes.Hash(self.chosen_hash, default_backend())
				hasher.update(message['typeMSG'].encode())
				hasher.update(str(message['auctionType']).encode())
				hasher.update(message['cryptoPuzzle'].encode())
				hasher.update(str(message['numOfZeros']).encode())
				digest = hasher.finalize()

				signature = self.utils.sign_msg(self.private_key, digest)
			
			else:
				# Get the type of the auction
				auctionType = self.returnTypeOfAuction(msg['serialNb'],self.clAuctLst)

				# Construct answer to send to client
				message = { 
					'typeMSG' : 'answer', 
					'auctionType' : auctionType
				}

				# Generate the repository signature
				hasher = hashes.Hash(self.chosen_hash, default_backend())
				hasher.update(message['typeMSG'].encode())
				hasher.update(str(message['auctionType']).encode())
				digest = hasher.finalize()

				signature = self.utils.sign_msg(self.private_key, digest)

			# Return message and inform client about the auction type and cryptopuzzle
			self.send(json.dumps({
				'message' : message,
				'signature' : base64.b64encode(signature).decode('utf-8')
			}),self.client)

		elif typeMSG == 'winnings':
			msg = self.message['message']

			# Extract client's signature
			client_signature = base64.b64decode(self.message['signature'])
			# Get client's certificate from message
			client_certificate = base64.b64decode(msg["certificate"])
			certDer = x509.load_der_x509_certificate( client_certificate, default_backend() )
			
			# Extract public key
			pubKey = certDer.public_key()

			# Create signature for message
			hasher = hashes.Hash(self.chosen_hash, default_backend())
			hasher.update(msg['typeMSG'].encode())
			hasher.update(bytes(msg['serialNb']))
			hasher.update(msg['certificate'].encode())
			digest = hasher.finalize()

			#Verify Signature 
			try:
				pubKey.verify(client_signature,digest,padding.PKCS1v15(), self.chosen_hash)
				print(' > CLIENT SIGNATURE IS VALID')
			except InvalidSignature:
				print(' > SIGNATURE IS INVALID')
			except Exception as e:
				print(" ERROR: SIGNATURE IS INVALID")
				print(e.args)
				return None

			results = self.showResults(msg['serialNb'])

			message = {'results': results}
		
			# Generate the repository signature
			hasher = hashes.Hash(self.chosen_hash, default_backend())
			hasher.update(str(message['results']).encode())
			digest = hasher.finalize()

			signature = self.utils.sign_msg(self.private_key, digest)

			# Return message and inform client about the auction type
			self.send(json.dumps({
				'message' : message,
				'signature' : base64.b64encode(signature).decode('utf-8')
			}),self.client)

		elif typeMSG == 'verifyCryptoPuzzle':
			msg = self.message['message']
			
			# Get client signature
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
				self.utils.verify(client_certificate , chain)
				print( " > CERTIFICATE CHAIN IS VALID" )
			except ValueError:
				print( " > CERTIFICATE CHAIN ISN\'T VALID" )
				return
			except Exception as e:
				print( " > ERROR OCCURED WHILE CHECKING CERTIFICATE CHAIN " )
				print( " > ERROR: {}".format(e) )
				return		

			#https://cryptography.io/en/latest/hazmat/primitives/asymmetric/rsa/?highlight=signature
			hasher = hashes.Hash(self.chosen_hash, default_backend())
			hasher.update(msg['typeMSG'].encode())
			hasher.update(str(msg['inputCryptopuzzle']).encode())
			hasher.update(str(msg['result']).encode()),
			hasher.update(msg['certificate'].encode()),
			hasher.update(str(msg['chain']).encode())
			digest = hasher.finalize()

			try:
				pubKey.verify(client_signature,digest,padding.PKCS1v15(), self.chosen_hash)
				print(' > SIGNATURE IS VALID')
			except InvalidSignature:
				print(' > SIGNATURE IS INVALID')
				return
			except Exception as e:
				print("Signature not valid")
				print(e.args)
				return None

			# Check if crytopuzzle was successfully calculated
			toPuzzle = msg['inputCryptopuzzle']
			result = msg['result']

			hashed = self.utils.hash1(toPuzzle)
			if (result == hashed):
				print(" > CLIENT GENERATED THE RIGHT ANSWER TO CRYPTOPUZZLE")
				response = 1
			else:
				print(" > ERROR IN CRYPTOPUZZLE. ANSWER NOT PROPERLY CALCULATED")
				response = 0

			# Construct answer
			message = { 
				'typeMSG' : 'answerCryptoPuzzle',
				'response' : response 
			}	
		
			# Generate the repository signature
			hasher = hashes.Hash(self.chosen_hash, default_backend())
			hasher.update(message['typeMSG'].encode())
			hasher.update(str(message['response']).encode())
			digest = hasher.finalize()

			signature = self.utils.sign_msg(self.private_key, digest)

			# Return message and inform client about the auction type
			self.send(json.dumps({
				'message' : message,
				'signature' : base64.b64encode(signature).decode('utf-8')
			}),self.client)

		elif typeMSG == 'createAuction':

			msg = self.message['message']
			# Extract manager's signature from message
			man_signature = base64.b64decode(self.message['signature'])

			# Load Manger's public key
			with open('ManagerPubKey.pem', 'rb') as publicfile:
				pubkeydata = publicfile.read()

			man_pub_key = load_pem_public_key(pubkeydata,default_backend())

			# Create Signature
			hasher = hashes.Hash(self.chosen_hash, default_backend())
			hasher.update(msg['typeMSG'].encode())
			hasher.update(str(msg['serialNb']).encode())
			hasher.update(msg['auctionName'].encode())
			hasher.update(str(msg['auctionType']).encode())
			hasher.update(str(msg['timeLimit']).encode())
			hasher.update(msg['description'].encode())
			hasher.update(msg['dynamic_code'].encode())
			hasher.update(msg['certificate'].encode())
			digest = hasher.finalize()

			# Verify Signature 
			print(" > CHECKING MANAGER\'S SIGNATURE ")
			try:
				goodSignature = self.utils.verify_sign(man_pub_key,man_signature,digest)
				if goodSignature is None:
					print(" > SIGNATURE IS VALID")
			except InvalidSignature:
				print(" > SIGNATURE IS INVALID")
			except Exception as e:
				print("Signature not valid")
				print(e.args)
				return None

			# Launchs new thread in charge of the new auction
			print(" > LAUNCHING NEW AUCTION #{}".format(msg['serialNb']))  
			try:
				threading.Thread(target = self.launchThread, args = (msg,)).start()
			except Exception as e :
				print(" > ERROR: ".format(e))

		elif typeMSG == 'validateReceipt' : 

			msg = self.message['message']
			# Extract client's signature from message received
			client_signature = base64.b64decode(self.message['signature'])
			# Extract client's certificate from message received
			client_certificate = base64.b64decode( msg["certificate"])
			# Load certificate from bytes to X509.Certificate
			certDer = x509.load_der_x509_certificate( client_certificate, default_backend() )
			# Extract public key
			pubKey = certDer.public_key()

			## Create Signature
			hasher = hashes.Hash(self.chosen_hash, default_backend())
			hasher.update(msg['typeMSG'].encode())
			hasher.update(msg['certificate'].encode())
			hasher.update(bytes(msg['auctionNumber']))
			hasher.update(bytes(msg['blockNumber']))
			digest = hasher.finalize()

			#Verify Signature 
			try:
				pubKey.verify(client_signature,digest,padding.PKCS1v15(), self.chosen_hash)
				print(" > CLIENT\'S SIGNATURE IS VALID ")
			except InvalidSignature:
				print(" > CLIENT SIGNATURE IS INVALID ")
			except Exception as e:
				print(" ERROR: SIGNATURE IS INVALID")
				print(e.args)
				return None

			# Call function to verify that bid exists
			block = self.validateBid(msg['auctionNumber'], msg['blockNumber'])
			if block == None:
				block = []

			message = { 'block' : block }	

			# Generate the repository signature
			hasher = hashes.Hash(self.chosen_hash, default_backend())
			hasher.update(str(message['block']).encode())
			digest = hasher.finalize()

			signature = self.utils.sign_msg(self.private_key, digest)

			# Return block to the client
			self.send(json.dumps({
				'message' : message,
				'signature' : base64.b64encode(signature).decode('utf-8')
			}),self.client)

		elif typeMSG == 'retrieveBlock':

			msg = self.message['message']
			# Extract manager's signature from message
			man_signature = base64.b64decode(self.message['signature'])
			
			## Create Signature
			hasher = hashes.Hash(self.chosen_hash, default_backend())
			hasher.update(msg['typeMSG'].encode())
			hasher.update(str(msg['auctionNumber']).encode())
			hasher.update(str(msg['blockNumber']).encode())
			digest = hasher.finalize()

			# Load Manager's Public Key
			with open('ManagerPubKey.pem', 'rb') as publicfile:
				pubkeydata = publicfile.read()

			man_pub_key = load_pem_public_key(pubkeydata,default_backend())

			#Verify Signature 
			print(" > CHECKING MANAGER\'S SIGNATURE ")
			try:
				self.utils.verify_sign(man_pub_key,man_signature,digest)
				print(" > MANAGER SIGNATURE IS VALID ")
			except InvalidSignature:
				print(" > MANAGER SIGNATURE IS INVALID ")
			except Exception as e:
				print(" ERROR: SIGNATURE IS INVALID")
				print(e.args)
				return None

			# CALL FUNCTION TO VERIFY THAT THAT BID EXISTS
			block = self.validateBid(msg['auctionNumber'], msg['blockNumber'])
			if block == None:
				block = []

			message = { 'block' : block }	

			# Generate the repository signature
			hasher = hashes.Hash(self.chosen_hash, default_backend())
			hasher.update(str(message['block']).encode())
			digest = hasher.finalize()

			signature = self.utils.sign_msg(self.private_key, digest)

			# Return block to the client
			self.send(json.dumps({
				'message' : message,
				'signature' : base64.b64encode(signature).decode('utf-8')
			}),manager)

		elif typeMSG == 'terminateAuction':
			print(" > AUCTION ENDING EARLY.")

			msg = self.message['message']
			man_signature = base64.b64decode(self.message['signature'])

			# Load Manager's Public Key
			with open('ManagerPubKey.pem', 'rb') as publicfile:
				pubkeydata = publicfile.read()

			man_pub_key = load_pem_public_key(pubkeydata,default_backend())

			# Verify Manager's Signature
			hasher = hashes.Hash(self.chosen_hash, default_backend())
			hasher.update(msg['typeMSG'].encode())
			hasher.update(str(msg['serialNb']).encode())
			digest = hasher.finalize()

			try:
				print(" > CHECKING MANAGER\'S SIGNATURE ")
				self.utils.verify_sign(man_pub_key,man_signature,digest)
				print(" > SIGNATURE IS VALID")
			except InvalidSignature:
				print(" > SIGNATURE IS INVALID")
				return
			except Exception as e:
				print("ERROR: SIGNATURE IS INVALID")
				print(e.args)
				return 

			# Close auction specified by the manager
			self.remAuction(self.message['message']['serialNb'])

		elif typeMSG == 'listAuction':
			msg = self.message['message']

			# Extract client's signature from message received
			client_signature = base64.b64decode(self.message['signature'] )
			# Extract client's certificate from message received
			client_certificate = base64.b64decode( msg["certificate"] )
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
			hasher.update(msg['list'].encode())
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

			# Find out what type of list to send
			if msg['list'] == 'openAuctions':
				self.listAuction(self.opAuctLst)
			
			elif msg['list'] == 'closedAuctions':
				self.listAuction(self.clAuctLst)	

			elif msg['list'] == 'authorAuctions':	
				self.lock.acquire()
				try:
					#Get list of auctions still open created by the author
					authorList = list(filter(lambda auction: auction[0].author == self.message['message']['certificate'], self.opAuctLst))
					#Send list to author
					self.listAuction(authorList)

				except Exception as e:
					print('Exception Error: ' + str(e)) 
				finally:
					self.lock.release()

		elif typeMSG == 'makeBid':
			# Verify message received
			msg = self.message['message']

			auctionType = self.returnTypeOfAuction(msg['serialNb'],self.opAuctLst)
			
			# If english
			if auctionType == 0:
				auctionInfo = {
				    'AuctionType' : 0 ,
				    'biggestBid' : self.returnBiggestBid(msg['serialNb']), 
				    'dynamic_code' : self.returnDynamicCode(msg['serialNb']) 
				}

			# If blind
			else :
				# Extract client's signature
				client_signature = base64.b64decode(self.message['signature'])
				# Get client's certificate from message
				client_certificate = base64.b64decode( msg["certificate"])
				certDer = x509.load_der_x509_certificate( client_certificate, default_backend() )

				# Extract public key
				pubKey = certDer.public_key()

				# Verify the certificate chain		
				chain = []
				for cert in msg['chain']:
					chain.append(base64.b64decode(cert))

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

				# Create signature
				hasher = hashes.Hash(self.chosen_hash, default_backend())
				hasher.update(msg['typeMSG'].encode())
				hasher.update(str(msg['serialNb']).encode())
				hasher.update(str(msg['bidAmount']).encode())
				hasher.update(msg['certificate'].encode())
				hasher.update(str(msg['chain']).encode())
				digest = hasher.finalize()
				
				# Verify signature 
				print(' > CHECKING CLIENT SIGNATURE ')
				try:
					pubKey.verify(client_signature,digest,padding.PKCS1v15(), self.chosen_hash)
					print(' > SIGNATURE IS VALID')
				except InvalidSignature:
					print(' > SIGNATURE IS INVALID')
				except Exception as e:
					print(' > SIGNATURE IS INVALID')
					print(e.args)
					return None

				auctionInfo = {
				    'AuctionType' : 1,
				    'biggestBid' : -1,
				    'dynamic_code' : self.returnDynamicCode(msg['serialNb'])
				}

			# Create Repository signature 
			hasher = hashes.Hash(self.chosen_hash, default_backend())
			hasher.update(str(self.message['message']).encode())
			hasher.update(self.message['signature'].encode())
			hasher.update(str(auctionInfo).encode())
			digest = hasher.finalize()

			signature = self.utils.sign_msg(self.private_key, digest)

			# Save original client address
			client_add = self.client
			
			# CHECK VALIDITY OF BID
			# Send bid to manager to check if it is valid
			self.send(json.dumps({
				'message' : self.message['message'],
				'signature' : self.message['signature'],
				'auctionInfo' : auctionInfo,
				'signature_repo' : base64.b64encode(signature).decode('utf-8')
			}), manager)

			# Receive answer from manager
			super().receive()

			# Check validity of message received from Manager
			man_signature = base64.b64decode(self.message['signature_man'])

			# Load Manager's public key
			with open('ManagerPubKey.pem', 'rb') as publicfile:
				pubkeydata = publicfile.read()

			man_pub_key = load_pem_public_key(pubkeydata,default_backend())

			# Check manager's signature
			hasher = hashes.Hash(self.chosen_hash, default_backend())
			hasher.update(str(self.message['message']).encode())
			hasher.update(self.message['signature'].encode())
			hasher.update(str(self.message['bidValidity']).encode())
			digest = hasher.finalize()

			print(' > CHECKING MANAGER\'S SIGNATURE')
			self.utils.verify_sign(man_pub_key,man_signature,digest)
			print(' > SIGNATURE IS VALID')

			self.client = client_add

			block = None

			if self.message['bidValidity']['validBid'] == True :
				# Make bid
				block = self.makeBid(
					self.message['message']['serialNb'],
					self.message['message']['bidAmount'],
					self.message['message']['certificate']
				).__dict__()

			# Construct message signature
			hasher = hashes.Hash(self.chosen_hash, default_backend())
			hasher.update(str(self.message['message']).encode())
			hasher.update(self.message['signature'].encode())
			hasher.update(str(self.message['bidValidity']).encode())
			hasher.update(self.message['signature_man'].encode())
			hasher.update(str(block).encode())
			digest = hasher.finalize()

			signature = self.utils.sign_msg(self.private_key, digest)

			# Send answer to client
			self.send(json.dumps({
				'message' : self.message['message'],
				'signature' : self.message['signature'],
				'bidValidity' : self.message['bidValidity'],
				'signature_man' : self.message['signature_man'],
				'block' : block,
				'signature_repos' : base64.b64encode(signature).decode('utf-8')
			}),self.client)


		elif typeMSG == 'listBid':
			# Verify message received
			msg = self.message['message']

			print('sdf')

			# Extract message's signature
			client_signature = base64.b64decode(self.message['signature'])
			# Extract message's certificate 
			client_certificate = base64.b64decode( msg["certificate"])
			certDer = x509.load_der_x509_certificate( client_certificate, default_backend() )
			# Extract public key from the client certificate
			pubKey = certDer.public_key()

			# Verify the certificate chain		
			chain = []
			for cert in msg['chain']:
				chain.append(base64.b64decode(cert))

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

			# Create signature
			hasher = hashes.Hash(self.chosen_hash, default_backend())
			hasher.update(msg['typeMSG'].encode())
			hasher.update(msg['list'].encode())
			hasher.update(bytes(msg['serialNb']))
			hasher.update(msg['certificate'].encode())
			hasher.update(str(msg['chain']).encode())
			digest = hasher.finalize()

			# Verifiy signature 
			try:
				print(" > CHECKING CLIENT\'S SIGNATURE")
				pubKey.verify(client_signature,digest,padding.PKCS1v15(), self.chosen_hash)
				print(" > SIGNATURE IS VALID")
			except InvalidSignature:
				print(" > SIGNATURE IS INVALID")
				return
			except Exception as e:
				print("Signature not valid")
				print(e.args)
				return None

			if self.message['message']['list'] == "auction_bids":
				self.getAuctionBids(self.opAuctLst, self.clAuctLst, msg['serialNb'])
			
			elif self.message['message']['list'] == 'validate_closed_auction':
				self.getAuctionBids([], self.clAuctLst, msg['serialNb']) 

			else:
				print("Unknown message type")

		elif typeMSG == 'decipherBlock':

			msg = self.message['message']
			# Extract manager's signature from message
			man_signature = base64.b64decode(self.message['signature'])
			
			## Create Signature
			hasher = hashes.Hash(self.chosen_hash, default_backend())
			hasher.update(msg['typeMSG'].encode())
			hasher.update(str(msg['block']).encode())
			digest = hasher.finalize()

			# Load Manager's Public Key
			with open('ManagerPubKey.pem', 'rb') as publicfile:
				pubkeydata = publicfile.read()

			man_pub_key = load_pem_public_key(pubkeydata,default_backend())

			#Verify Signature 
			print(" > CHECKING MANAGER\'S SIGNATURE ")
			try:
				self.utils.verify_sign(man_pub_key,man_signature,digest)
				print(" > MANAGER SIGNATURE IS VALID ")
			except InvalidSignature:
				print(" > MANAGER SIGNATURE IS INVALID ")
				return True
			except Exception as e:
				print(" ERROR: SIGNATURE IS INVALID")
				print(e.args)
				return True

			# Save deciphered block in a list 
			self.saveDecipheredBlock(msg['block'])
	
	#Launch thread that creates new auctionmake
	def launchThread(self, message):
		self.lock.acquire()
		try:
			#Create first block in new blockchain 
			blockchain = [Block(0,'Repository',0,message['serialNb'],"0")]
			
			#Add it to list of open auctions
			self.opAuctLst.append([Auction(	
				message['certificate'],message['auctionName'],
				message['serialNb'],message['auctionType'],
				message['timeLimit'],message['description'],
				message['dynamic_code']),blockchain])
		
		except Exception as e:
			print('  > ERROR WHILE TRYING TO LAUNCH THREAD')
			print('  > ERROR: {}'.format(e)) 
		
		finally:
			self.lock.release()
		
			#Wait for time limit to expire
			time.sleep(message['timeLimit'])
			# Close auction specified by the manager
			self.remAuction(message['serialNb'])

	#Remove auction from list
	def remAuction(self,serialNb):
		# Acquire lock
		self.lock.acquire()
		try:
			#Add auction to be removed to closed auctions list
			auctionList = list(filter(lambda x: x[0].serialNb == serialNb , self.opAuctLst))

			if auctionList != []:
				# Add closed auction to list of closed auctions
				self.clAuctLst.append(auctionList[0])
				# Remove auction from list of open auctions
				auctionList = list(filter(lambda x: x[0].serialNb != serialNb , self.opAuctLst))
				self.opAuctLst = auctionList			
				print(" > AUCTION #{} CLOSED".format(serialNb))
			
			else: 
				print(" > AUCTION #{} NOT FOUND, PROBABLY TERMINATED EARLY".format(serialNb))

		except Exception as e:
			print(' > ERROR OCCURED WHILE CLOSING AUCTION: ',e)
		finally:
			# Release lock
			self.lock.release()
 
	#Send list of auctions belonging to author back to him
	def listAuction(self,auctList):
		self.lock.acquire()

		print(auctList)

		try:
			listAuction = [auction[0].__dict__() for auction in auctList]

			hasher = hashes.Hash(self.chosen_hash, default_backend())
			hasher.update(str(listAuction).encode())
			digest = hasher.finalize()

			signature = self.utils.sign_msg(self.private_key, digest)

			print("AUCTIONS BY AUTHOR: ",listAuction)
			
			self.send(json.dumps({
				'message': listAuction,
				'signature': base64.b64encode(signature).decode('utf-8')
			}), self.client)                        
		
		except Exception as e:
			raise
		
		finally:
			self.lock.release()

	#Add new bid block to blockchain
	def makeBid(self,serialNb,bidAmount,certificate):
		self.lock.acquire()
		
		newBlock = None

		try:
			# Get auction where the bid is going to be added 
			auction = list(filter(lambda x: x[0].serialNb == serialNb , self.opAuctLst))
			# Get blockchain associated with auction
			blockchain = auction[0][1]
			# Calculate bid ID
			newID = len(blockchain)
			# Get author name
			author = certificate
			# Generate new block
			newBlock = Block(newID,author,bidAmount,serialNb,blockchain[-1].hash)			
			# Append bid to the end of blockchain
			blockchain.append(newBlock)

		except Exception as e:
			raise
		finally:
			self.lock.release()
			return newBlock

	def getAuctionBids(self, opAuctLst, clAuctLst, serialNb):	
		self.lock.acquire()
		try:	
			auction = list(filter(lambda x: x[0].serialNb == serialNb , opAuctLst))
			if auction != []:
				blockchain = auction[0][1]
				print(blockchain)
				result = [block.__dict__() for block in blockchain]

				hasher = hashes.Hash(self.chosen_hash, default_backend())
				hasher.update(str(result).encode())
				digest = hasher.finalize()
				signature = self.utils.sign_msg(self.private_key, digest)

				self.send(json.dumps({
					'message': result,
					'signature': base64.b64encode(signature).decode('utf-8')
					}),self.client)
			else: 
				auction = list(filter(lambda x: x[0].serialNb == serialNb , clAuctLst))
				if auction != []:
					blockchain = auction[0][1]
					print(blockchain)
					result = [block.__dict__() for block in blockchain]

					hasher = hashes.Hash(self.chosen_hash, default_backend())
					hasher.update(str(result).encode())
					digest = hasher.finalize()
					signature = self.utils.sign_msg(self.private_key, digest)
					self.send(json.dumps({
						'message': result,
						'signature': base64.b64encode(signature).decode('utf-8')
					}),self.client)
				else:
					hasher = hashes.Hash(self.chosen_hash, default_backend())
					hasher.update(str([]).encode())
					digest = hasher.finalize()
					signature = self.utils.sign_msg(self.private_key, digest)
					self.send(json.dumps({
						'message' : [],
						'signature': base64.b64encode(signature).decode('utf-8')
					}),self.client)
					print(" > NO AUCTION WITH SERIAL NUMBER " + str(serialNb) + " CURRENTLY OPEN." )
		finally:
			self.lock.release()

	def returnTypeOfAuction(self, serialNb, auction_list):
		# Search auction with serial number = auctionNumber
		# and return the type of the auction (0 or 1)
		# If auction that does not exist return -1
		self.lock.acquire()

		auctionType = list(filter(lambda x: x[0].serialNb == int(serialNb) , auction_list))
		#print(auctionType)
		self.lock.release()

		if not auctionType:
			return -1	
		else :
			return auctionType[0][0].auctType

	def returnBiggestBid(self, serialNb):
		self.lock.acquire()

		auction = list(filter(lambda x: x[0].serialNb == int(serialNb) , self.opAuctLst))
		blockchain = auction[0][1]
		bid = blockchain[-1].bid
		#print(auctionType)
		self.lock.release()

		return bid

	def returnDynamicCode(self, serialNb):
		self.lock.acquire()
		
		auction = list(filter(lambda x: x[0].serialNb == int(serialNb) , self.opAuctLst))
		
		self.lock.release()

		return auction[0][0].dynamic_code

	def validateBid(self,auctionNumber, blockNumber):
		self.lock.acquire()
		try:
			#Add auction to be removed to closed auctions list
			blockChain = list(filter(lambda x: x[0].serialNb == auctionNumber , self.clAuctLst))[0][1]
			block = list(filter(lambda block: block.index == blockNumber , blockChain))[0]

			if blockChain != [] and block != []:
				return block.__dict__()

				#auctionList = list(filter(lambda x: x[0].serialNb != serialNb , self.opAuctLst))
				#self.opAuctLst = auctionList
			
		except Exception as e:
			print('Exception Error: ' + str(e))
		finally:
			self.lock.release()

	def showResults(self, auctionNumber):
		self.lock.acquire()
		try:
			#Add deciphered block to the list of deciphered blocks in closed auctions
			deciphered_block_list = list(filter(lambda x: x[0].serialNb == auctionNumber, self.clAuctLst))[0][2]
			print(deciphered_block_list)
			return deciphered_block_list
		except IndexError:
			# If the list of deciphered blocks doesn't exist yet, create it and then add the block it  
			return []
		except Exception as e:
			print("ERROR OCCURED")
		finally:
			print(self.clAuctLst)
			self.lock.release()

	def saveDecipheredBlock(self, block):
		self.lock.acquire()

		try:
			#Add deciphered block to the list of deciphered blocks in closed auctions
			deciphered_block_list = list(filter(lambda x: x[0].serialNb == block['serialNb'], self.clAuctLst))[0]
			deciphered_block_list[2].append(block)
		except IndexError:
			# If the list of deciphered blocks doesn't exist yet, create it and then add the block it  
			deciphered_block_list.append(list())
			deciphered_block_list[2].append(block)
		except Exception as e:
			print("ERROR OCCURED")
		finally:
			print(self.clAuctLst)
			self.lock.release()

if __name__ == "__main__":
	server = Repository(12356)
	while True:
		print('\n > REPOSITORY SERVER WAITING FOR NEW MESSAGE.')
		server.receive()
