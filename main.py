import json
from datetime import timedelta,datetime
from fastapi import FastAPI,File,UploadFile
from models import User
from mongoengine import connect
from fastapi import Depends,HTTPException
from pydantic import BaseModel
from passlib.context import CryptContext
from fastapi.security import OAuth2PasswordBearer,OAuth2PasswordRequestForm
from jose import jwt
import pandas as pd
from fastapi.responses import FileResponse


#creating instance 
app=FastAPI()

#connecting with the database (mongodb using mongoengine)
connect(db="application",host="localhost",port=27017)


#importing BaseModel from pydantic which allows us to map the structure of the db.
class NewUser(BaseModel):
    username:str
    email:str
    password:str

# hasing the password.
password_context=CryptContext(schemes=["bcrypt"],deprecated="auto")

def get_password_hash(password):
    return password_context.hash(password)


# For User Registration
@app.post("/register")

#passing the Base Model
def register(new_user:NewUser):
    user=User(username=new_user.username,
              email=new_user.email,
              password=get_password_hash(new_user.password))
    user.save()
    return {"message":"registration succesfull"}


oauth2_scheme=OAuth2PasswordBearer(tokenUrl="token")

#Authenticating user
def authenticate(username,password):
    try:
        user=json.loads(User.objects.get(username=username).to_json())
        password_check=password_context.verify(password,user['password'])
        return password_check
    except User.DoesNotExist:
        return False

SECRET_KEY="wrqtfecvtby7Y3#jkgb@hih&"
ALGORITHM="HS256"

#creating token with jwt encoding
def create_access_token(data:dict,expires_delta:timedelta):
    to_encode=data.copy()
    expire=datetime.utcnow()+expires_delta
    to_encode.update({"exp":expire})

    encoded_jwt=jwt.encode(to_encode,SECRET_KEY,algorithm=ALGORITHM)

    return encoded_jwt

#login functionality
@app.post("/token")

def login(form_data:OAuth2PasswordRequestForm=Depends()):
    username=form_data.username
    password=form_data.password

    if authenticate(username,password):
        access_token=create_access_token(
            data={"sub":username},expires_delta=timedelta(minutes=30)
        )
        return {"access_token":access_token,"token_type":"bearer"}
    else:
        return HTTPException(status_code=400,detail="Incorrect username and password")



#convert excel to csv
@app.post("/")

def ExcelToCSV(file:UploadFile=File(...),form_data:OAuth2PasswordRequestForm=Depends()):
    data=pd.read_excel(file.file.read())
    data.to_csv("new.csv",index=None,header=True)
    
    data_csv=pd.read_csv("new.csv")
    
    username=form_data.username
    password=form_data.password
    if authenticate(username,password):
        return FileResponse("new.csv")
    else:
        if (len(data_csv)>100):
            return {"message":"Register to upload files larger than 100"}
        else:
            return FileResponse("new.csv")
