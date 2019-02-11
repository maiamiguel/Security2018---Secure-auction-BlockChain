import sys
import json
import socket

from Utils import *
from Auction import Auction

class Server(object):

	def __init__(self):
		# Creating socket
		self.server_socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
		# Address from most recent message
		self.client = None
		# Most recent message received
		self.message = None
		# Utils class
		self.utils = Utils()
		# Chosen hash
		self.chosen_hash = hashes.SHA1()

	def bind(self,port):
		#Binding socket to port
		print(" > BINDING UDP SOCKET TO PORT" , port)
		self.server_socket.bind(('0.0.0.0',port))

	# Server's send function
	def send(self,message,destination_address):
		# Tell destination amount of bytes being sent
		self.server_socket.sendto(json.dumps({
			"byte_amount" : len(message.encode())
		}).encode(),destination_address)

		# Wait for destination to respond
		self.server_socket.recvfrom(4096)[0]
		
		#Send the actual message
		self.server_socket.sendto(message.encode(),destination_address)

	# Server's receive function
	def receive(self):
		#Receives first message telling server the amount of bytes comming
		data, self.client = self.server_socket.recvfrom(4096)
		byte_amount = json.loads(data.decode())['byte_amount']
		print(" > WAITING TO RECEIVE " + str(byte_amount) + " BYTES.")
	
		#Tells the client it's ready to start receiving
		self.server_socket.sendto(json.dumps('YES').encode(),self.client)
	
		#Receives the actual message
		data, self.client = self.server_socket.recvfrom(byte_amount)
		self.message = json.loads(data.decode())
		#print(" > NEW MESSAGE RECEIVED: " + str(self.message))
		print(" > NEW MESSAGE RECEIVED ")
