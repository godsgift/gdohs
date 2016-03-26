from pymongo import *
from config import DB_Name, DB_User, DB_Pass

client = MongoClient()
#To run db
#mongod --dbpath data --smallfiles -- auth

#Start up script to create the empty database with empty collections/tables
def main():
	db = client[DB_Name]
	#Create user to connect to the database
	db.add_user(DB_User, DB_Pass, roles=["readWrite"])
	db.authenticate(DB_User, DB_Pass, source=DB_Name)
	
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