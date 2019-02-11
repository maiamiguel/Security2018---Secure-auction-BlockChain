import hashlib, json

class Block(object):

	def __init__(self,index,author,bid,serialNb,prev_hash):
		self.index = index
		self.author = author
		self.bid = bid
		self.serialNb = serialNb
		self.prev_hash = prev_hash
		self.hash = self.hash_block()

	def hash_block(self):
		
		sha = hashlib.sha256()
		
		sha.update((str(self.index) + 
				   str(self.author) +
				   str(self.bid) +
				   str(self.serialNb) +
				   str(self.prev_hash)).encode('utf-8'))
		
		return sha.hexdigest()

	def __str__(self):
		return "Block #" + '{:03d}'.format(self.index) + " Client: " + self.author + " Bid amount: " + str('{:03d}'.format(self.bid)) + "\nHash: " + self.hash
		pass

	def __dict__(self):
		return {
			#'Client' : self.author,
			'index' : self.index,
			'author' : self.author,
			'bid' : self.bid,
			'serialNb' : self.serialNb,
			'prev_hash' : self.prev_hash,
			'hash' : self.hash
		}

	def __eq__(self,AuctionSN):
		return self.serialNb == AuctionSN