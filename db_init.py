# db_init.py

import re
from app import create_app
from models import db, User, Transaction
from passlib.hash import pbkdf2_sha256
import pandas as pd
from datetime import datetime

app = create_app()

@app.cli.command('initdb')
def init_db_command():
    """Flask CLI命令: flask initdb"""
    with app.app_context():
        db.drop_all()  # clear all tables
        db.create_all()
        print("Database tables created.")

@app.cli.command('importxl')
def import_from_excel():
    """读取 Excel 并插入到数据库的命令: flask importxl"""
    with app.app_context():
        # read excel file named transactions.xlsx
        df = pd.read_excel('transactions.xlsx')

        # loop through each row in the DataFrame and insert into the database
        for idx, row in df.iterrows():
            raw_account = str(row['Account No']).strip()
            account_no = re.sub(r'\D', '', raw_account)  # clean up account number, remove non-digit characters

            date_str = row['DATE']  # might be a string or datetime
            transaction_details = row.get('TRANSACTION DETAILS', '')
            chq_no = row.get('CHQ.NO.', '')
            value_date_str = row.get('VALUE DATE', None)
            withdrawal_amt = row.get('WITHDRAWAL AMT', None)
            deposit_amt = row.get('DEPOSIT AMT', None)
            balance_amt = row.get('BALANCE AMT', None)

            # process date and value date
            try:
                date_parsed = pd.to_datetime(date_str)
            except:
                date_parsed = datetime.now()

            try:
                value_date_parsed = pd.to_datetime(value_date_str) if pd.notnull(value_date_str) else None
            except:
                value_date_parsed = None

            # check if user exists
            user = User.query.filter_by(account_no=account_no).first()
            if not user:
                # if not, create a new user
                user = User(
                    account_no=account_no,
                    username=f"user_{account_no}",
                    password_hash=pbkdf2_sha256.hash('DefaultPass123')
                )
                db.session.add(user)
                db.session.commit()

            # create a new transaction
            tx = Transaction(
                user_id=user.id,
                account_no=account_no,
                date=date_parsed,
                transaction_details=transaction_details,
                chq_no=str(chq_no) if pd.notnull(chq_no) else None,
                value_date=value_date_parsed,
                withdrawal_amt=float(withdrawal_amt) if pd.notnull(withdrawal_amt) else None,
                deposit_amt=float(deposit_amt) if pd.notnull(deposit_amt) else None,
                balance_amt=float(balance_amt) if pd.notnull(balance_amt) else None
            )
            db.session.add(tx)

        db.session.commit()
        print("Excel data imported successfully!")


if __name__ == '__main__':
    with app.app_context():
        from models import db
        db.create_all()

        # input function
        import_from_excel()

