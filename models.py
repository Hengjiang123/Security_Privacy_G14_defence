# models.py

from flask_sqlalchemy import SQLAlchemy
from datetime import datetime

db = SQLAlchemy()

class User(db.Model):
    __tablename__ = 'users'
    id = db.Column(db.Integer, primary_key=True)

    # add new field for account number, unique for each user
    account_no = db.Column(db.String(50), unique=True, nullable=False)
    username = db.Column(db.String(64), unique=True, nullable=True)
    password_hash = db.Column(db.String(128), nullable=False)

    # here can be other fields like email, phone number, etc.
    created_at = db.Column(db.DateTime, default=datetime.utcnow)

    def __repr__(self):
        return f'<User {self.account_no}>'


class Transaction(db.Model):
    __tablename__ = 'transactions'
    id = db.Column(db.Integer, primary_key=True)

    # connection to User table
    user_id = db.Column(db.Integer, db.ForeignKey('users.id'), nullable=False)
    user = db.relationship('User', backref='transactions')

    # store excel data
    account_no = db.Column(db.String(50), nullable=False) 
    date = db.Column(db.DateTime, nullable=False)
    transaction_details = db.Column(db.String(255))
    chq_no = db.Column(db.String(50))
    value_date = db.Column(db.DateTime)
    withdrawal_amt = db.Column(db.Float, nullable=True)
    deposit_amt = db.Column(db.Float, nullable=True)
    balance_amt = db.Column(db.Float, nullable=True)

    def __repr__(self):
        return f'<Transaction {self.id} {self.account_no}>'
