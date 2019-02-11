import json

class Auction(object):
	def __init__(self, author, 
			name, serialNb, 
			auctType, timeLimit,
			description, dynamic_code):

		super(Auction, self).__init__()
		self.author = author
		self.name = name
		self.serialNb = serialNb 
		self.auctType = auctType
		self.timeLimit = timeLimit
		self.description = description
		self.dynamic_code = dynamic_code

	def __str__(self):
		return "Auction: " + self.name + " Type: " + str('{:01d}'.format(self.auctType)) + " Serial: #" + str('{:03d}'.format(self.serialNb)) + " Time Limit:" + str('{:02d}'.format(self.timeLimit)) + "s.\n Description: " + self.description
	
	def __dict__(self):
		return {
			'Author' : self.author,
			'Name' : self.name,
			'serialNb' : self.serialNb,
			'Auction type' : self.auctType,
			'Time limit' : self.timeLimit,
			'Description' : self.description,
			'Dynamic Code' : self.dynamic_code
		}

#	def __eq__(self,AuctionSN):
#		return self.serialNb == AuctionSN