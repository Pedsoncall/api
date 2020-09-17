
import jwt
import json
import pyodbc
#import pymysql 
import datetime
import urllib.parse


from flask import Flask,request,jsonify,redirect, url_for
from flask_sqlalchemy import SQLAlchemy
from flask_httpauth import HTTPBasicAuth, HTTPTokenAuth, MultiAuth

from passlib.apps import custom_app_context as pwd_context

from flask_mail import Mail, Message

from random import randint
from flask import make_response
from flask_cors import CORS

basic_auth = HTTPBasicAuth()
token_auth = HTTPTokenAuth('Bearer')
multi_auth = MultiAuth(basic_auth, token_auth)




app = Flask(__name__)
CORS(app)

#app.config['SQLALCHEMY_DATABASE_URI'] = 'mysql://root:root1234@localhost/myappdb'

#params = urllib.parse.quote_plus("DRIVER={FreeTDS};SERVER=myrds.caa8mx0j14uc.us-east-2.rds.amazonaws.com;PORT=1433;UID=admin;PWD=admin123!;DATABASE=devdb")
#app.config['SQLALCHEMY_DATABASE_URI'] = "mssql+pyodbc:///?odbc_connect=%s" % params

params = urllib.parse.quote_plus("DRIVER={FreeTDS};SERVER=pedsoncall.cp42nrzgcaom.us-west-1.rds.amazonaws.com;PORT=1433;UID=Sudarshan;PWD=Sudarshan;DATABASE=Pedsoncall")
app.config['SQLALCHEMY_DATABASE_URI'] = "mssql+pyodbc:///?odbc_connect=%s" % params

app.config.update(
	MAIL_SERVER='smtp.gmail.com',
	MAIL_PORT=465,
	MAIL_USE_SSL=True,
    MAIL_USERNAME = 'dummyforpassreset@gmail.com',
    MAIL_PASSWORD = 'dummy@123'
	#MAIL_USERNAME = 'techsupport@pedsoncall.net',
	#MAIL_PASSWORD = 'Welcome@Pedsoncall'
	)
mail = Mail(app)

db = SQLAlchemy(app)

my_secret="This is the secret key"


generated_otps={ }

#______________________________________________________________ flask http auth ___________________________________________________________________________________#


class Admin(db.Model):
    __tablename__ = 'admin'

    username = db.Column(db.String(32), primary_key = True)
    password_hash = db.Column(db.String(128))
    active= db.Column(db.Boolean,default=False)
    phone_no=db.Column(db.String(30))
    email=db.Column(db.String(30))
    role=db.Column(db.String(30),default="user")


    def hash_password(self, password):
        self.password_hash = pwd_context.encrypt(password)

    def verify_password(self, password):
        return pwd_context.verify(password, self.password_hash) 

    def generate_auth_token(self, expiration = 600):
        time = datetime.datetime.utcnow() + datetime.timedelta(seconds=7200)
        encoded_jwt = jwt.encode({'username': self.username,'exp':time}, my_secret, algorithm='HS256')
        return encoded_jwt

    def verify_auth_token(self,token):
        data=jwt.decode(token, my_secret, algorithms=['HS256'])
        user = User.query.get(data['username'])
        return user    

    def get_roles(self):
        return self.role


class patientDetails(db.Model):
    __tablename__ = 'patientDetails'
    id = db.Column(db.Integer,autoincrement = True,primary_key=True,nullable=False)
    uniqueId = db.Column(db.String(200),nullable=False)
    patientFirstName = db.Column(db.String(100),nullable = False)
    patientLastName = db.Column(db.String(100),nullable=False)
    dob = db.Column(db.String(50))
    clientName = db.Column(db.String(100))
    pcpName = db.Column(db.String(100))
    callerNumber = db.Column(db.String(15))
    details=db.Column(db.String(80000),nullable=False)

    def setUniqueId(self,DOB):
        self.uniqueId = str(self.patientFirstName) + str(self.patientLastName) + str(DOB)
        return True

@basic_auth.verify_password
def verify_password(username, password):
    user = Admin.query.filter_by(username = username).first()
    if not user or not user.verify_password(password) or not user.active:
        return False
    return user


@token_auth.verify_token
def verify_token(token):
    print("in token")
    data=jwt.decode(token,my_secret, algorithms=['HS256'])
    user = Admin.query.filter_by(username=data["username"]).first()
    if not user or not user.active:
        return False
    return user

@token_auth.get_user_roles
def get_user_roles(user):
    return user.get_roles()


#______________________________________________________________ flask http auth ends _______________________________________________________________________________#



#login 

@app.route('/')
@multi_auth.login_required
def index():
    print("in protected route")
    user = multi_auth.current_user()
    print(user.username)
    token = user.generate_auth_token()
    send={ }
    send["token"]=token.decode('utf-8')
    send["username"]=user.username
    send["role"]=user.role
    return send
    

@app.route('/admin_check',methods=["GET"])
@multi_auth.login_required(role="admin")
def admin_check():

    return {"admin":"true"}

@app.route('/user_check',methods=["GET"])
@multi_auth.login_required
def user_check():

    return {"user":"true"}

#______________________________________________________________ reg & delete  _______________________________________________________________________________#


@app.route('/register', methods = ['POST'])
def new_user():
    postdata=request.get_json(force=True)
    username = postdata["username"]
    password = postdata["password"]
    phone_no=postdata["phone_no"]
    email=postdata["email"]
    
    if username is None or password is None:
        abort(400) # missing arguments

    user = Admin(username = username,phone_no=phone_no,email=email)
    user.hash_password(password)
    

    db.session.add(user)
    db.session.commit()
    #print("user created")
    return "true"

@app.route('/delete',methods=['POST'])
@multi_auth.login_required(role="admin")
def delete():
    postdata=request.get_json(force=True)
    user = Admin.query.filter_by(username=postdata["username"]).first()
    db.session.delete(user)
    db.session.commit()
    return {user.username:"deleted"}

#______________________________________________________________ reg & delete ends _______________________________________________________________________________#


#______________________________________________________________ status routes _______________________________________________________________________________#


@app.route('/make_active',methods=['POST'])
@multi_auth.login_required(role="admin")
def make_active():
    postdata=request.get_json(force=True)

    user = Admin.query.filter_by(username=postdata["username"]).first()
    user.active=True
    db.session.commit()
    return {user.username:user.active}

@app.route('/make_in_active',methods=['POST'])
@multi_auth.login_required(role="admin")
def make_in_active():
    postdata=request.get_json(force=True)

    user = Admin.query.filter_by(username=postdata["username"]).first()
    user.active=False
    db.session.commit()
    return {user.username:user.active}


#______________________________________________________________ status routes end _____________________________________________________________________________#


#______________________________________________________________ role routes ___________________________________________________________________________________#

@app.route('/make_admin',methods=['POST'])
@multi_auth.login_required(role="admin")
def make_admin():
    postdata=request.get_json(force=True)

    user = Admin.query.filter_by(username=postdata["username"]).first()
    user.role='admin'
    db.session.commit()
    return {user.username:user.role}


@app.route('/make_user',methods=['POST'])
@multi_auth.login_required(role="admin")
def make_user():
    postdata=request.get_json(force=True)

    user = Admin.query.filter_by(username=postdata["username"]).first()
    user.role='user'
    db.session.commit()
    return {user.username:user.role}


#______________________________________________________________ role routes end _______________________________________________________________________________#




@app.route('/send_otp',methods=["POST"])
def send_mail():
    postdata=request.get_json(force=True)
    
    user = Admin.query.filter_by(username=postdata["username"]).first()
    mailid=user.email
    
    otp = randint(100000, 999999) 
    
    generated_otps[user.username]=str(otp)

    msg = Message(
    subject="Forgot Password OTP",
    body ="Dear "+user.username+' the OTP to reset your password is '+str(otp),
    sender="techsupport@pedsoncall.net",
    recipients=[mailid])
    
    mail.send(msg)

    return {"status":"sent"}
    


@app.route('/validate_resetpass_otp',methods=['POST'])
def validate_resetpass_otp():
    postdata=request.get_json(force=True)
    otp=postdata["otp"]
    username=postdata["username"]

    
    print(username)
    print(generated_otps)
    print(type(generated_otps[username]))
    print(type(otp))
    if(generated_otps[username]==str(otp)):
        return {"otp_status":"correct"}
    

    return {"otp_status":"wrong"}


@app.route('/reset_password',methods=['POST'])
def reset_password():
    postdata=request.get_json(force=True)
    user = Admin.query.filter_by(username=postdata["username"]).first()

    user.hash_password(postdata["new_password"])
    db.session.commit()
    return {"reset_status":"true"}


@app.route('/sample',methods=["POST"])
def sample():
    postdata=request.get_json(force=True)
    data = { }
    data["send"]=postdata
    return data


@app.route('/getall')
def getall():
    users = Admin.query.all()
    data=[]
    for user in users :
        u={}
        u["username"]=user.username
        u["role"]=user.role
        u["active"]=user.active
        u["email"]=user.email
        u["phone"]=user.phone_no
        data.append(u)

    #print(data)
    return {"data":data}


#______________________________________________________________ test routes start _______________________________________________________________________________#


@app.route('/forms',methods=['POST','OPTIONS'])
def validateform():
    suda = request.json
    print(suda)
    return jsonify(suda)


@app.route('/getClients',methods = ["GET"])
def getClients():
    #conn = pyodbc.connect('DRIVER={FreeTDS};SERVER=petsoncall.cp42nrzgcaom.us-west-1.rds.amazonaws.com;PORT=1433;UID=Sudarshan;PWD=Sudarshan;DATABASE=Pedsoncall;'
    #                'Trusted_Connection=yes;')
    #cursor = conn.cursor()
    clientName = request.args.get("clientName")
    print("bef que")
    listOfClients = []
    sql = "SELECT PROVIDER_PCP_NAME FROM POC_ClientProfile WHERE CLIENT_NAME = '%s'"%(clientName)

    result = db.engine.execute(sql)
    print('aft que')
    #clients = cursor.execute('SELECT PROVIDER_PCP_NAME FROM Pedsoncall.Client.Profile')
    print(result)
    for row in result:
        print(row)
        listOfClients.append(row[0])

    return {"Clients":listOfClients}
    #return jsonify(result)


@app.route('/getClientName',methods = ["GET"])
def getClientName():
    listOfClientName = []
    sql = 'SELECT CLIENT_NAME,PROVIDER_PCP_NAME,CLIENT_CITY FROM POC_ClientProfile'
    result = db.engine.execute(sql)
    for row in result:
        print(row)
        listOfClientName.append(row[0] +  ' - ' + row[1] + ' ' + row[2])
    return {"ClientName":listOfClientName}


@app.route('/diagCode',methods = ["GET"])
def diagCode():

    diagCode = []
    sql = 'SELECT [codeid],[description],[codegroup] FROM [Pedsoncall].[dbo].[POC_DiagCode]'
    result = db.engine.execute(sql)
    print('aft que',flush=True)
    #print(result)
    for row in result:
        #print(row,flush=True)
        temp={ }
        temp['codeid']=row[0]
        temp['description']=row[1]
        temp['codegroup']=row[2]
        diagCode.append(temp)
    
    return {"diagCode":diagCode}

#______________________________________________________________ test routes end _______________________________________________________________________________#



#______________________________________________________________ query routes start _______________________________________________________________________________#
'''
@app.route('/registerPatient', methods = ["POST"])
def registerPatient():
    formData = request.get_json(force=True)
    #formData = request.json
    print(formData)
    PatientFirstName = formData["personalDetails"]["patientFirstName"]
    patientLastName = formData["personalDetails"]["patientLastName"]
    registerPatient = patientDetails(patientFirstName=PatientFirstName,patientLastName=patientLastName,details="Inserted into db")
    registerPatient.setUniqueId(formData["personalDetails"]["dob"])

    print(registerPatient.uniqueId)

    #registerPatients.setUniqueId(formData['personalDetails']['dob'])
    db.session.add(registerPatient)
    db.session.commit()
    #print(formData['personalDetails']['patientFirstName'])
    return formData
'''

@app.route('/registerPatient', methods = ['POST'])
def registerPatient():
    formData = request.get_json(force=True)
    
    patientFirstName = formData["personalDetails"]["patientFirstName"]
    patientLastName = formData["personalDetails"]["patientLastName"]
    dob = formData["personalDetails"]["dob"]
    clientName = formData["personalDetails"]["client"]
    pcpName = formData["personalDetails"]["pcp"]
    callerNumber = formData["personalDetails"]["callerNumber"]
    details = json.dumps(formData)

    print(details,flush=True)
   
    print(len(details),flush=True)

   
    uniqueId = patientFirstName+patientLastName+dob
    
    sql = "INSERT INTO patientDetails(uniqueId,patientFirstName,patientLastName,dob,clientName,pcpName,callerNumber,details) VALUES ('%s','%s','%s','%s','%s','%s','%s','%s');"%(uniqueId,patientFirstName,patientLastName,dob,clientName,pcpName,callerNumber,details)
    result = db.engine.execute(sql) 
    db.session.commit()
    return details



@app.route('/searchPatient',methods = ['POST'])
def searchPatient():
  
    searchForm = request.get_json(force=True)
    #print(searchForm,flush=True)
    #patientFirstName = searchForm["patientFirstName"]
    #print(patientFirstName,flush=True)
    #patientLastName = searchForm["patientLastName"]
    #print(patientLastName,flush=True)
    #dob = searchForm["dobSearch"]
    #uniqueId = searchForm["uniqueId"]
    #clientName = searchForm["client"]
    #pcpName = searchForm["pcp"]
    #callerNumber = searchForm["callerNumber"]
    flag = 0
    dynamicQuery = "SELECT CAST(details as TEXT) FROM [Pedsoncall].[dbo].[patientDetails] WHERE "
    for x in searchForm:
        if(searchForm[x]!=''):
            if(flag==0):
                if(x=='patientFirstName' or x=='patientLastName'):
                    dynamicQuery = dynamicQuery + x + ' LIKE ' + "'"+searchForm[x]+"%'"
                else:
                    dynamicQuery = dynamicQuery + x + ' = ' + "'"+searchForm[x]+"'" 
                flag = 1
            else:
                if(x=='patientFirstName' or x=='patientLastName'):
                    dynamicQuery = dynamicQuery + ' AND ' + x + ' LIKE ' + "'"+searchForm[x]+"%'"
                else:
                    dynamicQuery = dynamicQuery + ' AND ' + x + ' = ' + "'"+searchForm[x]+"'"


    print(dynamicQuery,flush=True)
    #uniqueId = patientFirstName + patientLastName + dob

    myList = []

    #sql = "SELECT CAST(details as TEXT) FROM [Pedsoncall].[dbo].[patientDetails] WHERE uniqueId = '%s'"%(uniqueId)
    result = db.engine.execute(dynamicQuery) 

    for row in result:
        print(row[0],flush=True)
        myList.append(json.loads(row[0]))

    
    return { "result" : myList }


@app.route('/searchPatientNew',methods = ['POST'])
def searchPatientNew():
    searchForm = request.get_json(force=True)
    uniqueId = searchForm["uniqueId"]
    sql = "SELECT [details] FROM [Pedsoncall].[dbo].[patientDetails] WHERE uniqueId = '%s'"%(uniqueId)
    result = db.engine.execute(sql)
    print(result)
    print(type(result),flush=True)


    myDict = {}
    for row in result:
        myDict["personalDetails"]["patientFirstName"] = row[0][0]
    print(myDict,flush=True)
    #searchResult = json.loads(result)
    #print(searchResult,flush=True)
    return "Search Success!"



#______________________________________________________________ query routes end _______________________________________________________________________________#
if __name__ == '__main__':
    app.run(host="0.0.0.0",port="80",debug=True)
    #app.run(debug=True)



    '''
{"personalDetails": {"patientFirstName": "David", "patientLastName": "Warner", "callerName": "Mike Tyson", "providerName": "user", "dob": "07/08/2020", "phoneNumber": "1234567890", "startTime": "13/08/2020, 11:22:00", "endTime": null, "pcp": "BRIAN GREENBERG"}, "medicalDetails": {"allergies": "N/A", "meds": "N/A", "pmh": "N/A", "fh": "N/A", "sh": "N/A", "cc": "N/A", "hpi": "N/A", "ros": "N/A", "exam": "N/A", "diagnosis": "N/A", "plan": "N/A", "coding": "N/A"}, "callDetails": {"startTime": null, "endTime": null}}
    '''



'''
{<>personalDetails<>: {<>patientFirstName<>: <>abc2<>, <>patientLastName<>: <>xyz<>, <>callerName<>: <>dw<>, <>providerName<>: <>user<>, <>dob<>: <>01/01/00<>, <>phoneNumber<>: <>asa<>, <>startTime<>: <>13/08/2020, 12:46:12<>, <>endTime<>: None, <>pcp<>: <>FRANK XU<>}, <>medicalDetails<>: {<>allergies<>: <>cvs<>, <>meds<>: <>and<>, <>pmh<>: <>div<>, <>fh<>: <>fav<>, <>sh<>: <>fds\n\n<>, <>cc<>: <>fav<>, <>hpi<>: <>vs<>, <>ros<>: <>df<>, <>exam<>: <>fvs<>, <>diagnosis<>: <>dvs<>, <>plan<>: <>dvs<>, <>coding<>: <>dsvsd<>}, <>callDetails<>: {<>startTime<>: None, <>endTime<>: None}}
hey
{<>personalDetails<>: {<>patientFirstName<>: <>abc2<>, <>patientLastName<>: <>xyz<>, <>callerName<>: <>dw<>, <>providerName<>: <>user<>, <>dob<>: <>01/01/00<>, <>phoneNumber<>: <>asa<>, <>startTime<>: <>13/08/2020, 12:46:12<>, <>endTime<>: None, <>pcp<>: <>FRANK XU<>}, <>medicalDetails<>: {<>allergies<>: <>cvs<>, <>meds<>: <>and<>, <>pmh<>: <>div<>, <>fh<>: <>fav<>, <>sh<>: <>fds\n\n<>, <>cc<>: <>fav<>, <>hpi<>: <>vs<>, <>ros<>: <>df<>, <>exam<>: <>fvs<>, <>diagnosis<>: <>dvs<>, <>plan<>: <>dvs<>, <>coding<>: <>dsvsd<>}, <>callDetails<>: {<>startTime<>: None, <>endTime<>: None}}
'''
''' hey
{"personalDetails": {"consultationStartTime": "8/19/2020 06:56 PM", "consultationEndTime": "", "callerName": "s", "callerNumber": "s", "patientFirstName": "s", "patientLastName": "s", "providerName": "s", "dob": "s", "client": "HB PEDIATRICS", "pcp": "TAMMY LIU"}, "medicalDetails": {"allergies": ".", "meds": ".", "pmh": ".", "fh": ".", "sh": ".", "cc": ".", "hpi": ".", "ros": ".", "exam": ".", "plan": ".", "search": [], "coding": "."}}
'''