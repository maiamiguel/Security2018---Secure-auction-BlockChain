class DynamicCode:

	def run_dynamic_code(self,function, bid,highest_bid):
		#print(eval('dir()'))
		#print(eval('locals()'))
		#print(eval('globals()'))
		if function == 'nonexistent':
			print(" > NO DYNAMIC CODE TO RUN")
			return True
		else: 
			print(" > RUNNING DYNAMIC CODE")
			return eval(function, {'__builtins__' : None}, {'bid' : bid, 'highest_bid' : highest_bid})

if __name__ == "__main__":
	try:
		print(DynamicCode().run_dynamic_code('True if bid - highest_bid >= 5 else False',15,10))
	except Exception as e:
		print(e)

'''
Examples of functions to use
> ENGLISH
True if bid - highest_bid > 5 else False
True if bid % 2 == 0 else False
False if bid % 2 == 0 else True

> BLIND
'''
