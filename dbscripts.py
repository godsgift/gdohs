from pymongo import *

client = MongoClient()

#Start up script to create the empty database with empty collections/tables
def main():
	db = client['gdohs']
	#Create users table
	result = db.user.insert_one(
				{
					"username": "test"
				}
			)

	result = db.user.delete_many({})

	#Create license plate table
	result = db.license.insert_one(
				{
					"username": "test"
				}
			)

	result = db.license.delete_many({})

	#Create evetns table
	result = db.events.insert_one(
				{
					"username": "test"
				}
			)

	result = db.events.delete_many({})

	#Create reset password table
	result = db.resetpassword.insert_one(
				{
					"username": "test"
				}
			)

	result = db.resetpassword.delete_many({})

	#Create camera settings table
	result = db.settings.insert_one(
				{
					"username": "test"
				}
			)
	result = db.settings.delete_many({})

if __name__ == "__main__":
	main()