import pymongo
from pymongo import MongoClient
from main import app,bcrypt
from flask_pymongo import PyMongo





#cluster = MongoClient('mongodb+srv://simon:simo1223@cluster0.9tmqj.mongodb.net/sales?retryWrites=true&w=majority',tlsAllowInvalidCertificates=True)
cluster = MongoClient('mongodb://localhost/sales')
db = cluster["mydb"]
collection = db["mydb"]


#app.config["MONGO_URI"] = "mongodb+srv://simon:simo1223@cluster0.9tmqj.mongodb.net/sales?retryWrites=true&w=majority&ssl=true"
app.config["MONGO_URI"] = "mongodb://localhost/sales"
mongo = PyMongo(app)
