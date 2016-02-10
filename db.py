from pymongo import MongoClient

client = MongoClient()
# client = MongoClient("mongodb://mongodb0.example.net:27019")

#db = client.name of database
db = client.gdohs

#db.name of table
class user:

	def __init__(self, owner, pas, em, fname, lname):
		self.owner = owner
		self.pas = pas
		self.em = em
		self.fname = fname
		self.lname = lname

	def insert(self):
		result = db.user.insert_one(
			{
				"username": self.owner,
				"password": self.pas,
				"email": self.em,
				"firstname": self.fname,
				"lastname": self.lname
			}
		)
	

	# def adduser(owner, pas, em, fname, lname):


def license(license_plate):
	result = db.license.insert_one(
		)

newUser= user("test", "test123", "test@test.com", "EF", "Last")
newUser.insert()