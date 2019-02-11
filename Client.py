import os
import sys
import json
import socket
import base64
from CC import *
from Utils import *
from Block import *
from termcolor import colored

from cryptography.exceptions import *
from cryptography.hazmat.primitives.kdf.hkdf import HKDF

#EXPERIMENTAL
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives import padding
#from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from Crypto.PublicKey import RSA
from cryptography.hazmat.primitives import hashes  
from cryptography.hazmat.backends import default_backend  
from cryptography.hazmat.primitives.asymmetric import utils
from cryptography.hazmat.primitives.serialization import load_pem_public_key
from cryptography.hazmat.primitives.serialization import load_pem_private_key  
from cryptography.hazmat.primitives.serialization import load_der_public_key
from cryptography.hazmat.primitives.asymmetric import (
    padding, rsa, utils
)

class Client(object):

	def __init__(self):
		# Establish socket
		self.sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
		self.utils = Utils()
		self.chosen_hash = hashes.SHA1()

		#AES Key and iv in the bid that is necessary to hide the bid value
		self.key = os.urandom(32)
		self.iv = os.urandom(16)
		#AES Key and iv in the bid that is necessary to hide the certificate
		self.key_identity = os.urandom(32)
		self.iv_identity = os.urandom(16)
		
		try:
			# Citizen Card
			self.cc = CitizenCard()
			self.session = self.cc.PKCS11_session 
			self.cc.extract_certificates()
			self.certificate = self.cc.getCertificate('AUTHENTICATION')

			cert = x509.load_der_x509_certificate(self.certificate, default_backend())
			subject = cert.subject.get_attributes_for_oid(NameOID.COMMON_NAME)[0].value
			# Extract SmartCard subject name
			self.subject = subject
			# Extract SmartCard public key
			self.pubKey = cert.public_key()
			# Gets the certificate chain from the SmartCard
			self.chain = []
			for cert in self.cc.getChain(subject):
				self.chain.append(base64.b64encode(cert).decode('utf-8'))

			# Load repository's public key
			with open('RepositoryPubKey.pem', 'rb') as publicfile:
				pubkeydata = publicfile.read()
				publicfile.close()

			self.repo_pubKey = load_pem_public_key(pubkeydata,default_backend())

			# Load Manager's public key						
			with open('ManagerPubKey.pem', 'rb') as publicfile:
				pubkeydata = publicfile.read()
				publicfile.close()

			self.man_pubKey = load_pem_public_key(pubkeydata,default_backend())

		except Exception as e:
			print(colored(" > ERROR OCCURRED WHILE INITIALIZING CLASS",'red'))
			print(colored(" > CLOSING\n",'red'))
			exit()

	
	def menu(self):
		print("---------------------------------------")
		print(colored("0 - Create new auction", 'blue'))
		print(colored("1 - Terminate auction", 'blue'))
		print(colored("2 - List open auctions", 'blue'))
		print(colored("3 - List closed auctions", 'blue'))
		print(colored("4 - Send bid", 'blue'))
		print(colored("5 - Display all bids of an auction", 'blue'))
		print(colored("6 - Display all bids sent by a client", 'blue'))
		print(colored("7 - Validate a closed auction", 'blue'))
		print(colored("8 - Decypher bid", 'blue'))
		print(colored("9 - Validate a receipt and the bid", 'blue'))
		print(colored("10 - Check outcome of auction", 'blue'))
		print(colored("11 - Exit", 'blue'))
		print("---------------------------------------")

		while True:
			try:
				value = input(" > Introduce the number corresponding to the desired option -> ")
				option = self.option(int(value)) 
				return option
			except ValueError as e:
				print(colored(" > ERROR: Not valid input.",'red'))
			except Exception as e:
				print(colored(" > ERROR IN OPTION {}: {}".format(value,e),'red'))

	def option(self,opt):
		# Create auction		
		if opt == 0:
			# Ask client for the auction's name
			auctionName = input(" > Auction name ?\n > ")
			# If name is empty assign a default value
			if auctionName is '':
				print(colored(" > ASSIGNING DEFAULT VALUE 'default' ",'yellow'))
				auctionName = "default"

			# Ask what is the type of auction
			# Continue asking while the number given isn't 0 or 1
			while True:
				try:
					auctionType = int(input(" > Auction type: 0 for english | 1 for blind\n > "))
					if auctionType != 0 and auctionType != 1:
						raise ValueError
					break
				except ValueError:
					print(colored(" > ERROR: Auction type invalid. PLEASE INSERT 1 OR 0",'red'))
				except Exception as e:
					print(colored(" > ERROR: ".format(e),'red')) 

			# Ask how long the auction lasts
			# Continue asking while the input isn't a number
			while True:
				try:
					timeLimit = int(float(input(" > How long does the auction last ?\n > ")))
					break
				except ValueError:
					print(colored(" > ERROR: Not a valid input. PLEASE INSERT A NUMBER",'red'))
				except Exception as e:
					print(colored(" > ERROR: ".format(e),'red'))
			
			# Ask for a description of the auction 
			description = input(" > Description ?\n > ")
			# If the input is empty assign a default description
			if description is '':
				print(colored(" > ASSIGNING DEFAULT VALUE 'description' ",'yellow'))
				description = "description"

			# Ask for the dynamic code 
			while True:
				try: 
					dynamic_code = input(" > Use what dynamic code ?\n >" )
					# If the input is empty don't use any dynamic code
					if dynamic_code == '':
						print(colored(" > NOT USING DYNAMIC CODE ",'yellow'))
						dynamic_code = 'nonexistent'
					break
				except Exception as e:
					print(colored(" > ERROR: ".format(e),'red'))
					print(colored(" > NOT USING DYNAMIC CODE",'yellow'))
					dynamic_code = 'nonexistent'
					break

			# Create 'createAuction' message for manager
			message = { 
				'typeMSG' : 'createAuction',
				'auctionType' : auctionType,
				'auctionName' : auctionName,
				'timeLimit' : timeLimit,
				'description' : description, 
				'dynamic_code' : dynamic_code, 
				'certificate' : base64.b64encode(self.certificate).decode('utf-8'), 
				'chain' : self.chain
			}

			# Create signature for message
			hasher = hashes.Hash(self.chosen_hash, default_backend())
			hasher = hashes.Hash(self.chosen_hash, default_backend())
			hasher.update(message['typeMSG'].encode())
			hasher.update(message['auctionName'].encode())
			hasher.update(str(message['auctionType']).encode())
			hasher.update(str(message['timeLimit']).encode())
			hasher.update(message['description'].encode())
			hasher.update(message['dynamic_code'].encode()),
			hasher.update(message['certificate'].encode())
			hasher.update(str(message['chain']).encode())
		
			digest = hasher.finalize()
			
			# Sign with citizen card
			signature = self.cc.sign(digest)

			# Send message to manager
			self.createConnection('manager', json.dumps({
				'message' : message,
				'signature' : base64.b64encode(signature).decode('utf-8')
			}))
			
			return True

		# Terminate Auction
		elif opt == 1:
			# Create 'listAuction' message
			message = { 
				'typeMSG' : 'listAuction', 
				'list' : 'authorAuctions',
				'certificate' : base64.b64encode(self.certificate).decode('utf-8'),
				'chain' : self.chain
			}

			# Create signature for message
			hasher = hashes.Hash(self.chosen_hash, default_backend())
			hasher.update(message['typeMSG'].encode())
			hasher.update(message['list'].encode())
			hasher.update(message['certificate'].encode())
			hasher.update(str(message['chain']).encode())
			digest = hasher.finalize()

			# Sign with citizen card
			signature = self.cc.sign(digest)

			# Send message to repository
			self.createConnection('repository',json.dumps({
				'message' : message,
				'signature' : base64.b64encode(signature).decode('utf-8')
			}))

			# Receive list from Repository
			auctionList = json.loads(self.recvfromConnection())
			repo_signature = base64.b64decode(auctionList['signature'])

			# Assemble message's signature
			hasher = hashes.Hash(self.chosen_hash, default_backend())
			hasher.update(str(auctionList['message']).encode())
			digest = hasher.finalize()

			# Verify the repository signature 
			print(colored(" > CHECKING REPOSITORY SIGNATURE ",'yellow'))
			try:
				self.utils.verify_sign(self.repo_pubKey,repo_signature,digest)
				print(colored(' > REPOSITORY SIGNATURE IS VALID','green'))
			except InvalidSignature:
				print(colored(' > REPOSITORY SIGNATURE IS INVALID','red'))
				return True
			except Exception as e:
				print(colored(' > ERROR OCCURED WHILE TRYING TO VALIDATE REPOSITORY SIGNATURE \n > ERROR: {}'.format(e),'red'))
				return True

			# List auctions created by client
			auctionList = self.printAuction(auctionList['message'])
			if auctionList == [] : return True

			# Get serial number of auction to be terminated
			while True:
				try:
					serialNb = int(input(" > Terminate what auction ? \n > "))
					while serialNb not in auctionList:
						serialNb = int(input(" > Terminate what auction ? \n > "))
					break
				except ValueError:
					print(colored(" > ERROR: Not a valid input. PLEASE INSERT A NUMBER",'red'))

				except Exception as e:
					print(colored(" > ERROR: ".format(e),'red'))

			# Make message to send to manager
			message = { 
				'typeMSG' : 'terminateAuction', 
				'serialNb' : serialNb,
				'certificate' : base64.b64encode(self.certificate).decode('utf-8'),
				'chain' : self.chain
			}

			# Get message's signature 
			hasher = hashes.Hash(self.chosen_hash, default_backend())
			hasher.update(message['typeMSG'].encode())
			hasher.update(str(message['serialNb']).encode())
			hasher.update(message['certificate'].encode())
			hasher.update(str(message['chain']).encode())
			digest = hasher.finalize()

			# Sign with citizen card
			signature = self.cc.sign(digest)

			# Send message to manager
			self.createConnection('manager',json.dumps({
				'message' : message,
				'signature' : base64.b64encode(signature).decode('utf-8')
			}))

			return True

		# List open or closed auctions 
		elif opt == 2 or opt == 3 :
			# Make message to send to manager
			message = {
				'typeMSG' : 'listAuction',
				'list' : 'openAuctions' if opt == 2 else 'closedAuctions',
				'certificate' : base64.b64encode(self.certificate).decode('utf-8'),
				'chain' : self.chain	
			}

			# Get message's signature 
			hasher = hashes.Hash(self.chosen_hash, default_backend())
			hasher.update(message['typeMSG'].encode())
			hasher.update(message['list'].encode())
			hasher.update(message['certificate'].encode())
			hasher.update(str(message['chain']).encode())
			digest = hasher.finalize()

			signature = self.cc.sign(digest)

			# Send message to repository
			self.createConnection('repository',json.dumps({
				'message' : message,
				'signature' : base64.b64encode(signature).decode('utf-8')
			}))
			
			# Receive list from repository
			auctionList = json.loads(self.recvfromConnection())
			# Extract repository's signature from message
			repo_signature = base64.b64decode(auctionList['signature'])

			# Create signature
			hasher = hashes.Hash(self.chosen_hash, default_backend())
			hasher.update(str(auctionList['message']).encode())
			digest = hasher.finalize()

			# Verify Signature
			print(colored(" > CHECKING REPOSITORY SIGNATURE ",'yellow'))
			try:
				self.utils.verify_sign(self.repo_pubKey,repo_signature,digest)
				print(colored(" > REPOSITORY SIGNATURE IS VALID",'green'))
			except InvalidSignature:
				print(colored(" > REPOSITORY SIGNATURE IS INVALID", 'red'))
				return True
			except Exception as e:
				print(colored(' > ERROR OCCURED WHILE TRYING TO VALIDATE REPOSITORY SIGNATURE \n > ERROR: {}'.format(e),'red'))
				return True

			# Print auctions received from the repository
			self.printAuction(auctionList['message'])
			return True
		
		elif opt == 4:
			# Get the target auction's serial number
			# While value isn't an integer keep asking
			while True:
				try:
					serialNb = int(input(" > Target auction ?\n > "))
					break
				except ValueError:
					print(colored(" > ERROR: Not a valid input. PLEASE INSERT A NUMBER",'red'))
				except Exception as e:
					print(colored(" > ERROR: ".format(e),'red'))
			
			# Getting auction type 
			response = self.getAuctionType(serialNb,'make_bid')
			# Check validity of answer received
			auctionType = response['auctionType']
			if auctionType == -1:
				print(colored(" > AUCTION #{} DOESN'T EXIST OR IS ALREADY CLOSED".format(serialNb),'red'))
				return True	
				
			# SOLVING CRYPTOPUZZLE -------------------

			# Extract cryptopuzzle from the message
			cryptoPuzzle = response['cryptoPuzzle']
			# Extract number of zeros from the message
			numOfZeros = response['numOfZeros']
			# Generate and send Cryptopuzzle
			toPuzzle , result = self.utils.genCash(cryptoPuzzle, numOfZeros)
			
			# Make answer to send to repository
			message = { 
				'typeMSG' : 'verifyCryptoPuzzle', 
				'inputCryptopuzzle' : toPuzzle, 
				'result' : result, 
				'certificate' : base64.b64encode(self.certificate).decode('utf-8'),
				'chain' : self.chain
			} 

			# Get message's signature 
			hasher = hashes.Hash(self.chosen_hash, default_backend())
			hasher.update(message['typeMSG'].encode())
			hasher.update(str(message['inputCryptopuzzle']).encode())
			hasher.update(str(message['result']).encode())
			hasher.update(message['certificate'].encode())
			hasher.update(str(message['chain']).encode())
			digest = hasher.finalize()

			# Sign with citizen card
			signature = self.cc.sign(digest)

			# Send answer to repository
			self.createConnection('repository',json.dumps({
				'message' : message,
				'signature' : base64.b64encode(signature).decode('utf-8')
			}))

			# Receive answer from cryptopuzzle
			response = json.loads(self.recvfromConnection())

			# Extract repository's signature
			repo_signature = base64.b64decode(response['signature'])
			# Verify signature
			hasher = hashes.Hash(self.chosen_hash, default_backend())
			hasher.update(response['message']['typeMSG'].encode())
			hasher.update(str(response['message']['response']).encode())
			digest = hasher.finalize()

			#Verify signature 
			print(colored(" > CHECKING REPOSITORY SIGNATURE ",'yellow'))
			try:
				self.utils.verify_sign(self.repo_pubKey,repo_signature,digest)
				print(colored(' > REPOSITORY SIGNATURE IS VALID','green'))
			except InvalidSignature:
				print(colored(' > REPOSITORY SIGNATURE IS INVALID','red'))
				return True
			except Exception as e:
				print(colored(' > ERROR OCCURED WHILE TRYING TO VALIDATE REPOSITORY SIGNATURE \n > ERROR: {}'.format(e),'red'))
				return True

			# Extract response from message
			feedback = response['message']['response']
			# Check if response was accepted
			if feedback == 1:
				print(colored(" > CRYPTOPUZZLE ANSWER WAS ACCEPTED",'green'))
			else:
				print(colored(" > CRYPTOPUZZLE ANSWER WASN\'T ACCEPTED",'red'))
				return True
			
			# CREATING BID -------------------

			# Construct message that is going to be sent to client
			while True:
				try:					
					# Get bid value
					bidAmount  = int(input(" > Bid Amount ? \n > "))
					
					# If auction is Blind
					if auctionType == 1:
						# Cyphering bid amount	
						ciphertext = self.utils.AES_encrypt(self.key, self.iv, str(bidAmount) )
						# Turning bytes into string 
						bidAmount = base64.b64encode(ciphertext).decode('utf-8')
			
						# Constructing JSON message
						message = {
							'typeMSG' : 'makeBid', 
							'serialNb' : serialNb,
							'bidAmount' : bidAmount,
							'certificate' : base64.b64encode(self.certificate).decode('utf-8'),
							'chain' : self.chain
						}

						# Generating signature
						hasher = hashes.Hash(self.chosen_hash, default_backend())
						hasher.update(message['typeMSG'].encode())
						hasher.update(str(message['serialNb']).encode())
						hasher.update(str(message['bidAmount']).encode())
						hasher.update(message['certificate'].encode())
						hasher.update(str(message['chain']).encode())
						digest = hasher.finalize()

						signature = self.cc.sign(digest)

					# If auction is English
					elif auctionType == 0:
						# Get certificate in string format
						str_cert = base64.b64encode(self.certificate).decode('utf-8')
						# Get encrypted certificate
						certificate = self.utils.AES_encrypt(self.key_identity, self.iv_identity, str_cert)
										
						# Encrypt AES key used to encrypt certificate
						key = self.utils.RSA_encrypt(
							self.man_pubKey,json.dumps(
								{'identity' : base64.b64encode(self.key_identity).decode('utf-8'),
								'iv' : base64.b64encode(self.iv_identity).decode('utf-8')
								}
							).encode()
						)

						# Constructiong JSON message
						message = {
							'typeMSG' : 'makeBid',
							'serialNb' : serialNb,
							'bidAmount' : bidAmount,
							'certificate': base64.b64encode(certificate).decode('utf-8'),
							'chain' : self.chain,
							'key' : base64.b64encode(key).decode('utf-8')
						}

						# Generating signature
						hasher = hashes.Hash(self.chosen_hash, default_backend())
						hasher.update(message['typeMSG'].encode())
						hasher.update(str(message['serialNb']).encode())
						hasher.update(str(message['bidAmount']).encode())
						hasher.update(message['certificate'].encode())
						hasher.update(str(message['chain']).encode())
						hasher.update(message['key'].encode())
						digest = hasher.finalize()

						signature = self.cc.sign(digest)
						
					break
				except ValueError:
					print(colored(" > ERROR: BID AMOUNT HAS TO BE AN INTEGER VALUE",'red'))
				except Exception as e:
					print(colored(" > ERROR WHILE CONSTRUCTING MAKE BID MESSAGE FOR REPOSITORY. \n > ERROR: {}".format(e),'red'))
					return True
					
			# Send bid to repository
			self.createConnection('repository',json.dumps({
				'message' : message,
				'signature' : base64.b64encode(signature).decode('utf-8')
			}))

			# Wait to receive receipt
			receipt = json.loads(self.recvfromConnection())

			# Check to see if receipt is real
			repo_signature = base64.b64decode(receipt['signature_repos'])

			hasher = hashes.Hash(self.chosen_hash, default_backend())

			'''
			for key, value in receipt.items():
				print('KEY: ' ,key)
				print('VALUE:' ,value)
				hasher.update(value.encode()) if type(value) is str else hasher.update(str(value).encode())
			'''

			hasher.update(str(receipt['message']).encode())
			hasher.update(receipt['signature'].encode())
			hasher.update(str(receipt['bidValidity']).encode())
			hasher.update(receipt['signature_man'].encode())
			hasher.update(str(receipt['block']).encode())
			digest = hasher.finalize()

			#Verify Signature 
			print(colored(' > CHECKING REPOSITORY SIGNATURE','yellow'))
			try:
				self.utils.verify_sign(self.repo_pubKey,repo_signature,digest)
				print(colored(' > REPOSITORY SIGNATURE IS VALID','green'))
			except InvalidSignature:
				print(colored(' > REPOSITORY SIGNATURE IS INVALID\n > RECEIPT RECEIVED ISN\'T VALID','red'))
				return True
			except Exception as e:
				print(colored(' > ERROR OCCURED WHILE TRYING TO VALIDATE REPOSITORY SIGNATURE \n > ERROR: {}'.format(e.args),'red'))
				return True

			print(colored(" > CHECKING IF BID WAS ACCEPTED ",'yellow'))
			try:
				if receipt['bidValidity']['validBid']:
					print(colored(' > BID WAS ACCEPTED','green'))

					path = "Receipts"
					# Create the directory
					if not os.path.exists(path):
						os.mkdir(path)

					# Name of the directory where the receipt is stored
					path = os.path.join(path, self.subject)
					# Create the directory
					if not os.path.exists(path):
						os.mkdir(path)
					# Save receipt in a file
					with open(path+"/Auction : " + str(receipt['block']['serialNb']) + 
						" - Block : "+ str(receipt['block']['index']) +" .json", 'w') as outfile:
						json.dump(receipt, outfile)
						outfile.close()

				else:
					print(colored(' > BID WASN\'T ACCEPTED\n > ERROR: {}'.format(receipt['bidValidity']['Error']),'red'))

			except Exception as e:
				print(colored(' > ERROR OCCURED WHILE TRYING TO CHECK BID VALIDITY \n > ERROR: {}'.format(e.args),'red'))

			return True

		elif opt == 6:
			# Path where receipts are stored
			path = os.path.join("Receipts",self.subject)	
			# Get names of receipts
			receipts = [f for f in os.listdir(path) if os.path.isfile(os.path.join(path,f))]
			# Check if there are any receipts	
			if receipts == []:
				print(colored("\n > NO BIDS MADE IN ANY AUCTION\n",'red'))
			else:
				for r in receipts:
					with open(os.path.join(path,r), encoding='utf-8') as data_file:
						data = json.loads(data_file.read())
						print(colored(" > Auction #{} | Block #{} \n > Identity: {} | Amount {}€ ".format(data['block']['serialNb'], data['block']['index'], self.subject, data['block']['bid']),'yellow'))
						data_file.close()
				print("")		
			return True 

		elif opt == 5 or opt == 7:
			# Get auction serial number
			while True:
				try:
					auction_number = int(input(" > Auction Serial Number ? \n > "))
					break
				except ValueError:
					print(colored(" > ERROR: Not a valid input. PLEASE INSERT A NUMBER",'red'))
				except Exception as e:
					print(colored(" > ERROR: {}".format(e),'red'))

			#Create message
			message = {
				'typeMSG' : 'listBid',
				'list' : 'validate_closed_auction' if opt == 7 else 'auction_bids',
				'serialNb' : auction_number,
				'certificate' : base64.b64encode(self.certificate).decode('utf-8'),
				'chain' : self.chain
			}

			# Create signature for message
			hasher = hashes.Hash(self.chosen_hash, default_backend())
			hasher.update(message['typeMSG'].encode())
			hasher.update(message['list'].encode())
			hasher.update(bytes(message['serialNb']))
			hasher.update(message['certificate'].encode())
			hasher.update(str(message['chain']).encode())
			digest = hasher.finalize()

			signature = self.cc.sign(digest)

			#Send message to repository
			self.createConnection('repository',json.dumps({
				'message' : message,
				'signature' : base64.b64encode(signature).decode('utf-8')
			}))

			# Receive list from Repository
			bid_list = json.loads(self.recvfromConnection())
			# Extract repository signature
			signature = base64.b64decode(bid_list['signature'])

			# Create signature
			hasher = hashes.Hash(self.chosen_hash, default_backend())
			hasher.update(str(bid_list['message']).encode())
			digest = hasher.finalize()

			# Verify signature 
			print(colored(" > CHEKING REPOSITORY SIGNATURE",'yellow'))
			try:
				self.utils.verify_sign(self.repo_pubKey,signature,digest)
				print(colored(" > REPOSITORY SIGNATURE IS VALID",'green'))
			except InvalidSignature:
				print(colored(" > REPOSITORY SIGNATURE IS INVALID",'red'))
				return True
			except Exception as e:
				print(colored(' > ERROR OCCURED WHILE TRYING TO VALIDATE REPOSITORY SIGNATURE \n > ERROR: {}'.format(e),'red'))
				return True

			bid_list = bid_list['message']

			if bid_list == []:
				print(colored(" > AUCTION DOESN\'T EXIST",'red'))
			elif bid_list[1:] == []:
				print(colored(" > AUCTION DOESN\'T HAVE ANY BIDS",'red'))
			else:
				if opt == 5:
					self.printBid(bid_list[1:])
				else :
					for bid in bid_list:
						if bid['hash'] == Block(
							bid['index'],bid['author'],
							bid['bid'],bid['serialNb'],
							bid['prev_hash']	
						).hash:
							print(colored(" > BLOCK #{} IS VALID".format(bid['index']),'green'))
						else:
							print(colored(" > BLOCK #{} WAS TAMPERED WITH, WHOLE AUCTION IS INVALID".format(bid['index']),'red'))
							return True
					print(colored(" > AUCTION IS VALID",'green'))

			return True
		
		elif opt == 8:

			while True:
				
				# Ask for auction number
				# Stop asking only when value given is an integer
				while True:
					try:
						auction_number = int(input("Auction Serial Number ?\n -> "))
						break
					except ValueError:
						print(" > ERROR: Not a valid input. PLEASE INSERT A NUMBER")
					except Exception as e:
						print(" > ERROR: ".format(e))

				# Ask for block number
				# Stop asking only when value given is an integer
				while True:
					try:
						block_number = int(input("Auction Block Number ?\n -> "))
						break
					except ValueError:
						print(" > ERROR: Not a valid input. PLEASE INSERT A NUMBER")
					except Exception as e:
						print(" > ERROR: ".format(e))

				path = os.path.join('Receipts', self.subject, 'Auction : '+str(auction_number)+' - Block : '+str(block_number)+' .json')
				
				# If receipt exists exit loop
				if os.path.isfile(path) :
					break
				
				print(" > ERROR: RECEIPT FOR BID #{} IN AUCTION #{} DOESN\'T EXIST\n".format(block_number,auction_number))

			# Getting auction type 
			response = self.getAuctionType(auction_number,'get_type')
			# Check validity of answer received
			auctionType = response['auctionType']

			if auctionType == -1:
				print(" > AUCTION #{} DOESN'T EXIST.".format(auction_number))
				return True	

			if auctionType == 0:
				# Encrypt AES key used to encrypt certificate
				key = self.utils.RSA_encrypt(
					self.man_pubKey,json.dumps({
						'identity' : base64.b64encode(self.key_identity).decode('utf-8'),
						'iv' : base64.b64encode(self.iv_identity).decode('utf-8'),
						'field' : 'certificate'	
						}
					).encode()
				)

			else:
				# Encrypt AES key used to encrypt bid amount
				key = self.utils.RSA_encrypt(
					self.man_pubKey,json.dumps({
						'identity' : base64.b64encode(self.key).decode('utf-8'),
						'iv' : base64.b64encode(self.iv).decode('utf-8'),
						'field' : 'amount'
						}
					).encode()
				)

			# Load receipt
			with open(path, encoding='utf-8') as data_file:
				receipt = json.loads(data_file.read())
				data_file.close()

			# Construct message
			message = {
				'typeMSG' : 'decipherBlock',
				'receipt' : receipt, 
				'certificate' : base64.b64encode(self.certificate).decode('utf-8'),
				'chain' : self.chain,
				'key' : base64.b64encode(key).decode('utf-8'),
			}

			# Create Signature
			hasher = hashes.Hash(self.chosen_hash, default_backend())
			hasher.update(message['typeMSG'].encode())
			hasher.update(str(message['receipt']).encode())
			hasher.update(message['certificate'].encode())
			hasher.update(str(message['chain']).encode())
			hasher.update(message['key'].encode())

			digest = hasher.finalize()

			signature = self.cc.sign(digest)

			# Send message to manager
			self.createConnection('manager',json.dumps({
				'message' : message,
				'signature' : base64.b64encode(signature).decode('utf-8')
			}))

			# Get response from Manager 
			response = json.loads(self.recvfromConnection())
			# Extract repository signature
			man_signature = base64.b64decode(response['signature'])
			# Get signature from message received
			hasher = hashes.Hash(self.chosen_hash, default_backend())
			hasher.update(response['message']['answer'].encode())
			digest = hasher.finalize()

			#Verify Signature
			print(colored(" > CHEKING MANAGER SIGNATURE",'yellow'))
			try:
				self.utils.verify_sign(self.man_pubKey,man_signature,digest)
				print(colored(" > MANAGER SIGNATURE IS VALID",'green'))
			except InvalidSignature:
				print(colored(" > MANAGER SIGNATURE IS INVALID",'red'))
				return True
			except Exception as e:
				print(' > ERROR OCCURED WHILE TRYING TO VALIDATE MANAGER SIGNATURE \n > ERROR: {}',e)
				return True

			print(colored(' > {}'.format(response['message']['answer']).upper(),'green'))

			return True

		elif opt == 9:
		# validate a receipt.
		# verify the receipt signatures
		# make sure that the bid exists in the chain and that the values are correct

			while True:
				try:
					auctionNumber = int(input("Auction Serial Number ? -> "))
					break
				except ValueError:
					print(colored(" > ERROR: Not a valid input. PLEASE INSERT A NUMBER", 'red'))
				except Exception as e:
					print(colored(" > ERROR: ".format(e), 'red'))

			while True:
				try:
					blockNumber = int(input("Auction Block Number ? -> "))
					break
				except ValueError:
					print(colored(" > ERROR: Not a valid input. PLEASE INSERT A NUMBER", 'red'))
				except Exception as e:
					print(colored(" > ERROR: ".format(e), 'red'))

			path = "Receipts"
			# Name of the directory where the receipt is stored
			path = os.path.join(path, self.subject)
			# Create the directory
			path = path + "/Auction : " + str(auctionNumber) + " - Block : "+ str(blockNumber) +" .json"

			with open(path, encoding='utf-8') as data_file:
				data = json.loads(data_file.read())
				data_file.close()

			self.validateReceiptSignatures(path)

			message = {'typeMSG': 'validateReceipt', 'auctionNumber': auctionNumber,
			'blockNumber': blockNumber, 'certificate': base64.b64encode(self.certificate).decode('utf-8') }

			hasher = hashes.Hash(self.chosen_hash, default_backend())
			hasher.update(message['typeMSG'].encode())
			hasher.update(message['certificate'].encode())
			hasher.update(bytes(message['auctionNumber']))
			hasher.update(bytes(message['blockNumber']))
			digest = hasher.finalize()

			signature = self.cc.sign(digest)

			self.createConnection('repository',json.dumps({
				'message' : message,
				'signature' : base64.b64encode(signature).decode('utf-8')
			}))

			response = json.loads(self.recvfromConnection())

			hasher = hashes.Hash(self.chosen_hash, default_backend())
			hasher.update(str(response['message']['block']).encode())
			digest = hasher.finalize()

			signature = base64.b64decode(response['signature'])

			#Verify Signature 
			print(colored(" > CHEKING REPOSITORY SIGNATURE",'yellow'))
			try:
				self.utils.verify_sign(self.repo_pubKey,signature,digest)
				print(colored(" > REPOSITORY SIGNATURE IS VALID",'green'))
			except InvalidSignature:
				print(colored(" > REPOSITORY SIGNATURE IS INVALID",'red'))
			except Exception as e:
				print(' > ERROR OCCURED WHILE TRYING TO VALIDATE REPOSITORY SIGNATURE \n > ERROR: {}',e)
				return None

			block = response['message']['block']

			if block == []:
				print(colored(" > NO BLOCK FOUND. PLEASE MAKE SURE AUCTION WAS CLOSED",'red'))
			else:
				hashValue = response['message']['block']['hash']
				sha = hashlib.sha256()

				sha.update((str(response['message']['block']['index']) + 
							str(response['message']['block']['author']) +
							str(response['message']['block']['bid']) +
							str(response['message']['block']['serialNb']) +
							str(response['message']['block']['prev_hash'])).encode('utf-8'))
				
				hashVal = sha.hexdigest()

				if hashValue == hashVal:
					print(colored(" > THE BLOCK IS VALID",'green'))
				else:
					print(colored(" > BLOCK ISN\'T VALID. BLOCK CHAIN WAS TAMPERED WITH", 'red'))

			return True

		elif opt == 10:
			while True:
				try:
					auction_number = int(input("Auction Serial Number ? \n-> "))
					break
				except ValueError:
					print(" > ERROR: Not a valid input. PLEASE INSERT A NUMBER")
				except Exception as e:
					print(" > ERROR: ".format(e))

			#Create message
			message = {
				'typeMSG' : 'winnings',
				'serialNb' : auction_number,
				'certificate' : base64.b64encode(self.certificate).decode('utf-8'),
			}

			# Create signature for message
			hasher = hashes.Hash(self.chosen_hash, default_backend())
			hasher.update(message['typeMSG'].encode())
			hasher.update(bytes(message['serialNb']))
			hasher.update(message['certificate'].encode())
			digest = hasher.finalize()

			signature = self.cc.sign(digest)

			#Send message to repository
			self.createConnection('repository',json.dumps({
				'message' : message,
				'signature' : base64.b64encode(signature).decode('utf-8')
			}))

			# Receive list from Repository
			response = json.loads(self.recvfromConnection())

			hasher = hashes.Hash(self.chosen_hash, default_backend())
			hasher.update(str(response['message']['results']).encode())
			digest = hasher.finalize()

			repo_signature = base64.b64decode(response['signature'])

			#Verify Signature 
			print(colored(" > CHEKING REPOSITORY SIGNATURE",'yellow'))
			try:
				self.utils.verify_sign(self.repo_pubKey,repo_signature,digest)
				print(colored(" > REPOSITORY SIGNATURE IS VALID",'green'))
			except InvalidSignature:
				print(colored(" > REPOSITORY SIGNATURE IS INVALID",'red'))
				valid = False
			except Exception as e:
				print(' > ERROR OCCURED WHILE TRYING TO VALIDATE MANAGER SIGNATURE \n > ERROR: {}',e)
				return True

			results = response['message']['results']

			# Determine winner of an auction
			if results != []:
				maximum = results[0]['bid']

				for result in results:				
					if (result['bid'] > maximum):
						maximum = result['bid']

				for result in results:
					if (result['bid'] == maximum):
						thisOne = result
						break
						
				certificate = base64.b64decode(thisOne['author'])
				cert = x509.load_der_x509_certificate(certificate, default_backend())
				subject = cert.subject.get_attributes_for_oid(NameOID.COMMON_NAME)[0].value

				print(colored("\n > THE WINNER OF AUCTION {} WAS {} WITH A BID OF {}€\n".format(thisOne['serialNb'],subject,thisOne['bid']),'yellow'))
			else:
				print(colored("\n > EITHER THE AUCTION HASN\'T ENDED OR NO CLIENT HAS DECIPHERED THEIR BIDS YET",'red'))
			return True

		elif opt == 11:
			print(colored(' > CLOSING SOCKET','red'))
			self.sock.close()
			return False
		
		else:
			print(colored(" > ERROR: Option doesn't exist.",'red'))
			return True	

	def validateReceiptSignatures(self,path):
		valid = True

		# Load receipt
		with open(path, encoding='utf-8') as data_file:
			data = json.loads(data_file.read())
			data_file.close()

		# CLIENT SIGNATURE

		message = data['message']
		hasher = hashes.Hash(self.chosen_hash, default_backend())
		for key, value in message.items():
			hasher.update(value.encode()) if type(value) is str else hasher.update(str(value).encode())
		digest = hasher.finalize()
		
		client_signature = base64.b64decode(data['signature'])
		print(colored(" > CHECKING CLIENT SIGNATURE",'yellow'))
		try:
			self.pubKey.verify(client_signature,digest,padding.PKCS1v15(), self.chosen_hash)
			print(colored(" > CLIENT SIGNATURE IS VALID",'green'))
		except InvalidSignature:
			print(colored(" > CLIENT SIGNATURE IS INVALID",'red'))
			valid = False
		except Exception as e:
			print(colored(' > ERROR OCCURED WHILE TRYING TO VALIDATE CLIENT SIGNATURE \n > ERROR: {}'.format(e),'red'))
			valid = False

		# MANAGER SIGNATURE

		#Reconstructing manager signature
		hasher = hashes.Hash(self.chosen_hash, default_backend())
		hasher.update(str(data['message']).encode())
		hasher.update(data['signature'].encode())
		hasher.update(str(data['bidValidity']).encode())
		digest = hasher.finalize()

		man_signature = base64.b64decode(data['signature_man'])

		#Verify Signature 
		print(colored(" > CHECKING MANAGER SIGNATURE",'yellow'))
		try:
			self.utils.verify_sign(self.man_pubKey,man_signature,digest)
			print(colored(" > MANAGER SIGNATURE IS VALID",'green'))
		except InvalidSignature:
			print(colored(" > MANAGER SIGNATURE IS VALID",'red'))
			valid = False
		except Exception as e:
			print(colored(' > ERROR OCCURED WHILE TRYING TO VALIDATE MANAGER SIGNATURE \n > ERROR: {}'.format(e),'red'))
			valid = False

		# REPOSITORY SIGNATURE

		hasher = hashes.Hash(self.chosen_hash, default_backend())
		hasher.update(str(data['message']).encode())
		hasher.update(data['signature'].encode())
		hasher.update(str(data['bidValidity']).encode())
		hasher.update(data['signature_man'].encode())
		hasher.update(str(data['block']).encode())
		digest = hasher.finalize()

		repo_signature = base64.b64decode(data['signature_repos'])

		#Verify Signature 
		print(colored(" > CHECKING REPOSITORY SIGNATURE",'yellow'))
		try:
			self.utils.verify_sign(self.repo_pubKey,repo_signature,digest)
			print(colored(" > REPOSITORY SIGNATURE IS VALID",'green'))
		except InvalidSignature:
			print(colored(" > REPOSITORY SIGNATURE IS INVALID",'red'))
			valid = False
		except Exception as e:
			print(colored(' > ERROR OCCURED WHILE TRYING TO VALIDATE REPOSITORY SIGNATURE \n > ERROR: {}'.format(e),'red'))
			valid = False

		if valid:
			print(colored(" > ALL SIGNATURES WERE VERIFIED. RECEIPT IS VALID",'green'))
		else:
			print(colored(" > FOUND INVALID SIGNATURES IN RECEIPTL. RECEIPT IS INVALID",'red'))

		return True

	def createConnection(self,target, message):
		# Create a UDP socket
		if target == 'manager':
			server_address = manager
		elif target == 'repository':
			server_address = repository

		try:
			# Tell server amount of bytes being sent
			self.sock.sendto(json.dumps((
				{ "byte_amount" : len(message.encode())}
			)).encode(),server_address)
			
			# Wait for server to respond
			self.sock.recvfrom(4096)[0]

			#Send the actual message
			self.sock.sendto(message.encode(),server_address)
			print(colored(" > SENDING MESSAGE TO {}".format(target.upper()),'green'))
		
		except Exception as e:
			print(colored(" > ERROR WHILE TRYING TO SEND A MESSAGE\n > ERROR: {} ".format(e),'red'))

	def recvfromConnection(self):
		data, server = self.sock.recvfrom(4096)
		byte_amount = json.loads(data.decode())['byte_amount']
		#print(" > WAITING TO RECEIVE {} BYTES.".format(byte_amount))
	
		#Tells the client it's ready to star receiving
		self.sock.sendto(json.dumps('YES').encode(),server)

		#Receive the list
		return self.sock.recvfrom(byte_amount)[0]

	def printAuction(self, auctionlist):
		list = []
		print()
		if not auctionlist:
			print(colored(" > NO AUCTIONS FOUND ",'red'))
		else:
			for element in auctionlist: 
				print(colored(" > Auction #{} \'{}\', type {}, description - {} ".format(
					element["serialNb"],  element["Name"], element["Auction type"], element['Description'] 
				), 'yellow'))
				list.append(element["serialNb"])
		print()
		return list

	def printBid(self, bidlist):
		if bidlist == []:
			return
		#print(bidlist)
		print("")
		print(colored(" > LIST OF BIDS",'blue'))
		for element in bidlist: 
			print(colored(" > Auction #{} | Bid #{} | Amount {}€".format(
				element["serialNb"],element['index'],element["bid"] 
			),'blue'))
		print()

	# Function used by th client to get the type of an auction
	def getAuctionType(self, serial_number, option):
		# Make message to send to repository to get the type of auction
		message = { 
			'typeMSG' : 'getAuctionType',
			'option' : option,
			'serialNb' : serial_number, 
			'certificate': base64.b64encode(self.certificate).decode('utf-8'),
			'chain' : self.chain
		} 

		# Get message's signature 
		hasher = hashes.Hash(self.chosen_hash, default_backend())
		hasher.update(message['typeMSG'].encode())
		hasher.update(message['option'].encode())
		hasher.update(str(message['serialNb']).encode())
		hasher.update(message['certificate'].encode())
		hasher.update(str(message['chain']).encode())
		digest = hasher.finalize()

		signature = self.cc.sign(digest)

		# Send message to repository
		self.createConnection('repository',json.dumps({
			'message' : message,
			'signature' : base64.b64encode(signature).decode('utf-8')
		}))

		# Get response from repository
		response = json.loads(self.recvfromConnection())
		# Extract repositort's signature from the message
		repo_signature = base64.b64decode(response['signature'])

		# Get repository's signature
		hasher = hashes.Hash(self.chosen_hash, default_backend())
		hasher.update(response['message']['typeMSG'].encode())
		hasher.update(str(response['message']['auctionType']).encode())

		# If getAuctionType is being used by makeBid function, 
		# then there are 2 more camps in the message
		if option == 'make_bid':
			hasher.update(response['message']['cryptoPuzzle'].encode())
			hasher.update(str(response['message']['numOfZeros']).encode())
			
		digest = hasher.finalize()

		#Verify Signature 
		print(colored(' > CHECKING REPOSITORY SIGNATURE','yellow'))
		try:
			self.utils.verify_sign(self.repo_pubKey,repo_signature,digest)
			print(colored(' > REPOSITORY SIGNATURE IS VALID','green'))
		except InvalidSignature:
			print(colored(' > REPOSITORY SIGNATURE IS INVALID','red'))
			return True
		except Exception as e:
			print(colored(' > ERROR OCCURED WHILE TRYING TO VALIDATE REPOSITORY SIGNATURE \n > ERROR: {}'.format(e),'red'))
			return True

		# Extract auction type from the message
		return response['message']

if __name__ == "__main__":
	c = Client()
	while c.menu():
		pass
	print(colored(" > TERMINATING CLIENT",'red'))