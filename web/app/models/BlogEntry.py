from app import db
from sqlalchemy_serializer import SerializerMixin
import pytz
import datetime

class BlogEntry(db.Model, SerializerMixin):
    __tablename__ = "blog_entries"

    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(50))
    message = db.Column(db.String(280))
    email = db.Column(db.String(50))
    date_created = db.Column(db.String(50))
    date_updated = db.Column(db.String(50))
    ID_User = db.Column(db.Integer)

    def __init__(self, name, message, email, date_created ,owner_id):
        self.name = name
        self.message = message
        self.email = email
        self.date_created = date_created
        self.date_updated = None
        self.ID_User = owner_id

    def update(self, name, message, email,date_created):
        self.name = name
        self.message = message
        self.email = email
        self.date_updated = date_created