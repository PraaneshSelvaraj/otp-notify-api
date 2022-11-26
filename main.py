from flask import Flask
from flask_restful import Api, Resource, reqparse, abort
from typing import Dict, Any
import hashlib
import json
import secrets
import keys
from twilio.rest import Client
import os
from datetime import datetime
from flask_sqlalchemy import SQLAlchemy
import smtplib
from email.message import EmailMessage
from pymongo import MongoClient
import pymongo
from datetime import datetime
import templates

app = Flask(__name__)
api = Api(app)

#Conecting to MongoDB
mongo_client = MongoClient(keys.mongo_cluster)
db = mongo_client.otpnotify
users_collection = db.users
banks_collection = db.banks
logs_collection = db.logs

twilio_client = Client(keys.sid, keys.token)


#Arguments required to create Bank 
bank_creation_args = reqparse.RequestParser()
bank_creation_args.add_argument('name', required=True, type=str, help="Name of the Bank is required.")
bank_creation_args.add_argument('bin', required=True, type=int, help="Bank Identification Number is required.")

#Arugments required to get bank information
bank_info_args = reqparse.RequestParser()
bank_info_args.add_argument('secret', required=True, type=str, help="Api Secret is required.")
bank_info_args.add_argument('bin', required=True, type=int, help="Bank Identification Number is required.")

#Argumernts required to create User Account
user_create_args = reqparse.RequestParser()
user_create_args.add_argument('name', required=True, type=str, help="Name of the User is required.")
user_create_args.add_argument('username', required=True, type=str, help="username is required.")
user_create_args.add_argument('password', required=True, type=str, help="password is required.")
user_create_args.add_argument('account', required=True, type=str, help="Account number of the User is required.")
user_create_args.add_argument('mobile', required=True, type=str, help='Mobile Number of the user is required.')
user_create_args.add_argument('whatsapp', required=True, type=str, help='Whatsapp Number of the user is required.')
user_create_args.add_argument('email', required=True, type=str, help="Email of the User is required.")
user_create_args.add_argument('secondary_mobile', type=str, help="Secondary Mobile Number")
user_create_args.add_argument('call_enabled', required=True, type=str, help='True/False')
user_create_args.add_argument('whatsapp_enabled', required=True, type=str, help='True/False')
user_create_args.add_argument('email_enabled', required=True, type=str, help='True/False')
user_create_args.add_argument('secondary_call_enabled',required=True,type=str, help='True/False')
user_create_args.add_argument('secondary_message_enabled',required=True,type=str, help='True/False')

#Update User
update_user_args = reqparse.RequestParser()
update_user_args.add_argument('username', required=True, type=str, help='Username is required')
update_user_args.add_argument('password', required=True, type=str, help='Password is required')
update_user_args.add_argument('field', required=True, type=str, help='Field to be updated')
update_user_args.add_argument('value', required=True, type=str, help='Value to be updated')

#Argumernts required to get user information
user_info_args = reqparse.RequestParser()
user_info_args.add_argument('username', required=True, type=str, help="Username of the User is required.")
user_info_args.add_argument('password', required=True, type=str, help="Password of the User is required.")

#Arguments required to notify user
notify_args = reqparse.RequestParser()
notify_args.add_argument('account', required=True, type=str, help="Account number of the User is required.")
notify_args.add_argument('secret', required=True, type=str, help="Api Secret is required.")
notify_args.add_argument('bin', required=True, type=int, help="Bank Identification Number is required.")

#Arguments required to get logs
logs_args = reqparse.RequestParser()
logs_args.add_argument('username', required=True, type=str, help="Username is required.")
logs_args.add_argument('password', required=True, type=str, help="Password is required.")
logs_args.add_argument('count', required=True, type=int, help="Count of logs is required.")

def create_api_secret(dictionary):
    """Creates a secret by hashing the dictionary.

    Requires:
        dict -> dictionary -> dictionary containing user information.

    Returns:
        secret -> string -> MD5 hash of the dictionary.
    """
    dhash = hashlib.md5()
    encoded = json.dumps(dictionary, sort_keys=True).encode()
    dhash.update(encoded)
    
    return secrets.token_urlsafe(5) + dhash.hexdigest()

def make_call(mobile):
    """Makes a call to mobile using twilio api

    Requires: 
        mobile -> string -> Mobile number of user with country code. 
    """
    try:
        call = twilio_client.calls.create(
                    to=mobile,
                    from_= keys.twilio_num,
                    url='https://handler.twilio.com/twiml/EH7480c3083f58bada274facfea522ea4a'
                )
        return True
    except:
        return False

def send_whatsapp_message(whatsapp):
    """Sends a whatsapp message to the user using twilio api

    Requires:
        whatsapp -> string -> Whatsapp number of the user with country code.
    """
    try:
        message = twilio_client.messages.create(
            to='whatsapp:{}'.format(whatsapp),
            from_=keys.twilio_whatsapp,
            body='An OTP Has Been Sent from your bank. This message is sent to notify you.'
        )
        return True
    except Exception as e:
        print(e)
        return False

def send_message(mobile):
    """Sends a message using twilo api

    Requires:
        mobile -> string -> Mobile number of user
    """
    
    try:
        message = twilio_client.messages.create(
            body="An OTP Has Been Sent from your bank. This message is sent to notify you",
            from_=keys.twilio_num,
            to=mobile
        )
        return True
    except Exception as e:
        print(e)

def send_email(email):
    """Sends a email to the user using smtplib

    Requires:
        email -> string -> Email of user.
    """
    msg = EmailMessage()
    msg['From'] = keys.email
    msg['Subject'] = 'OTP Notification'
    msg['To'] = email
    msg.set_content(templates.email_template, subtype="html")


    try:
        server = smtplib.SMTP('smtp.gmail.com', 587)
        server.starttls()
        server.login(keys.email, keys.email_pwd)
        server.send_message(msg)
        return True

    except Exception as e:
        print(e)

class Create_Bank(Resource):
    #/bank/create
    def put(self):
        """ Registers Bank

        Requires:
            name -> string -> Name of the Bank.
            bin -> int -> Bank Identification Number.
        
        Returns:
            secret -> string -> Api secret to use while notifying.
        """
        args = bank_creation_args.parse_args()
        #checking if bank already exists
        bank = banks_collection.find_one({'bin':args['bin']})
        if bank:
            abort(409, message="Bank already registered.")
        else:
            #create a new api secret
            secret = create_api_secret(args)
            
            #adding the bank in database
            args['api_secret'] = secret
            args['date_created'] = datetime.utcnow()
            banks_collection.insert_one(args)
        
        return {'message':'Created Successfully', 'api_secret': secret}, 201

class Get_Bank_Info(Resource):
    #/bank
    def get(self):
        """Gets Bank information.

        Requires:
            secret -> string -> Api Seecret
            bin -> int -> Bank Identification Number
        Returns:
            
        """
        args = bank_info_args.parse_args()
        bank = banks_collection.find_one({'bin':args['bin']})
        
        if bank:
            if args['secret'] == bank['api_secret']:
                data = {'bin': bank['bin'], 'name': bank['name'], 'date_created': str(bank['date_created'])}
                return data
        else:
            abort(404, message="Bank not registered.")
        
            
class Create_User(Resource):
    #/user/create
    def put(self):
        """Registers User

        Requires:
            name -> string -> Name of the User.
            pan -> string -> PAN number of User.
            account -> string -> Account number of User.
            mobile -> string -> Mobile number of the User.
            whatsapp -> string -> Whatsapp number of the User.
            email -> string -> Email of the User.
            secondary_mobile -> string -> Secondary Mobile number of the User.

        Returns:
            secret -> string -> Api secret
        """
        args = user_create_args.parse_args()
        
        user = users_collection.find_one({'username':args['username']})
        try:
            a = args['secondary_mobile']
        except:
            args['secondary_mobile'] = 'None'

        if user:
            abort(409, message="Username already registered.")
        
        else:
            #create a new api secret
            secret = create_api_secret(args)
            
            #adding user in database
            args['secret'] = secret
            args['date_created'] = datetime.utcnow()

            users_collection.insert_one(args)
            return {'message':'Created Successfully', 'secret': secret}

class Get_User_Info(Resource):
    #/bank
    def get(self):
        """Gets User information.

        Requires:
            pan -> string -> Username
            
        Returns:
            
        """
        args = user_info_args.parse_args()
        user = users_collection.find_one({'username':args['username']})
        
        if user:
            if args['password'] == user['password']:
                data = {}
                for i in user:
                    if i == 'password' or i == "_id" or i =="secret": continue
                    else: 
                        data[i] = str(user[i])
                return data
        else:
            abort(404, message="Bank not registered.")

class Update_User(Resource):
    #/user/update
    def put(self):
        args = update_user_args.parse_args()
        if args['field'] not in ["password", "account", "mobile", "whatsapp", "email", "secondary_mobile", "call_enabled", "whatsapp_enabled", "email_enabled", "secondary_call_enabled", "secondary_message_enabled"]:
            abort(409, message="Unknown Field")

        user = users_collection.find_one({'username': args['username']})
        if user:
            if user['password'] == args['password']:
                users_collection.update_one({"_id":user['_id']}, {"$set":{args['field']:str(args['value'])}})
                return {"message": "Updated successfully."}
        else:
            abort(409,"Username does not exist")

class Notify(Resource):
    #/notify
    def post(self):
        """Notifys the User about OTP

        Requires:
            secret -> string -> Api secret
            account -> string -> Account number of the User.
            bin -> int -> Bank Identification Number
        """
        args = notify_args.parse_args()
        bank = banks_collection.find_one({'bin':args['bin']})

        if not bank:
            abort(404, message="Bank not registered.")
            return

        else:
            user = users_collection.find_one({'account':args['account']})
            if user:
                msg = {'message':'User has been notified.', }
                log = {"datetime" : datetime.utcnow(), "username": user['username'], "account":user['account']}
                #checking if call feature is enabled and mobile number is available
                if user['call_enabled'] == 'True' and user['mobile'] != "None":
                    #making call 
                    call = make_call(user['mobile'])
                    if call:
                        msg['call'] = 'True'
                        log['call'] = 'True'

                #checking if whatsapp feature is enabled and whatsapp number is available
                if user['whatsapp_enabled'] == 'True' and user['whatsapp'] != "None":
                    whatsapp_msg = send_whatsapp_message(user['whatsapp'])
                    if whatsapp_msg:
                        msg['whatsapp'] = 'True'
                        log['whatsapp'] = 'True'

                #checking if email feature is enabled and email is available.
                if user['email_enabled'] == 'True' and user['email'] != "None":
                    email_sent = send_email(user['email'])
                    if email_sent:
                        msg['email'] = 'True'       
                        log['email'] = 'True'

                #checking if secondary call feature is enabled and secondary mobile number is available
                if user['secondary_call_enabled'] == 'True' and user['secondary_mobile'] != "None":
                    secondary_call = make_call(user['secondary_mobile'])
                    if secondary_call:
                        msg['secondary_call'] = 'True'
                        log['secondary_call'] = 'True'

                #checking if secondary message feature is enabled and secondary mobile number is available.
                if user['secondary_message_enabled'] == 'True' and user['secondary_mobile'] != "None":
                    secondary_message = send_message(user['secondary_mobile'])
                    if secondary_message:
                        msg['secondary_message'] = 'True'
                
                logs_collection.insert_one(log)
            else:
                return {'message': 'unable to find '}
        return msg

class Get_Logs(Resource):
    #/user/logs
    def get(self):
        """Getting the logs of user from database

        Requires:
            username -> string -> Username
            password -> string -> Password
            count -> int -> count of logs to be returned

        Returns:
            list of logs
        """
        args = logs_args.parse_args()
        user = users_collection.find_one({'username': args['username']})
        if user:
            if user['password'] == args['password']:
                logs = logs_collection.find({'username': args['username']}).sort('datetime', pymongo.DESCENDING)
                if args['count'] != -1:
                    logs = logs.limit(args['count'])
                    
                data = {'logs':[]}
                for log in logs:
                    current = {}
                    for i in log:
                        if i == '_id': continue
                        current[i] = str(log[i])

                    data['logs'].append(current)
                return data
            else:
                abort(409, "Invalid password")
        else:
            abort(409, 'User not found')

api.add_resource(Create_Bank, '/bank/create')
api.add_resource(Get_Bank_Info, '/bank')
api.add_resource(Create_User, '/user/create')
api.add_resource(Notify, '/notify')
api.add_resource(Get_User_Info, '/user')
api.add_resource(Update_User, '/user/update')
api.add_resource(Get_Logs,'/user/logs')
if __name__ == '__main__':
    app.run(host='0.0.0.0', port=5000, debug=True)