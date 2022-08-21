from mongoengine import Document,StringField

class User(Document):
    username=StringField()
    email=StringField()
    password=StringField()