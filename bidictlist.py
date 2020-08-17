class Dictlist(dict):
	def __setitem__(self, key, value):
		try:
			self[key]
		except KeyError:
			super(Dictlist, self).__setitem__(key, [])
		self[key].append(value)
class BidirectionaDict(Dictlist):
	def __setitem__(self, key, val):
		Dictlist.__setitem__(self, key, val)
		Dictlist.__setitem__(self, val, key)
	def __delitem__(self, key):
		Dictlist.__delitem__(self, self[key])
		Dictlist.__delitem__(self, key)