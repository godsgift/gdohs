from itsdangerous import TimedJSONWebSignatureSerializer as Serializer, URLSafeSerializer
from pymongo import MongoClient
import json

client = MongoClient()
# client = MongoClient("mongodb://mongodb0.example.net:27019")

#db = client.name of database
db = client.gdohs


test = db.user.find_one({"username": "test"})



print test



# user = "test"

# s = URLSafeSerializer("super-secret-key")
# link = s.dumps(user)
# print link
# print s.loads(link)