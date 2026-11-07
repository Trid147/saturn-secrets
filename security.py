import bcrypt
from dotenv import load_dotenv
import jwt
import os
from datetime import datetime, timedelta, timezone

load_dotenv()

SECRET_KEY = os.getenv('SECRET_KEY')
if SECRET_KEY is None:
    raise RuntimeError('"SECRET KEY environmental variable is not set"')
ALGORITHM = 'HS256'

def hash_password(password: str) -> str:
    '''hashes password with salt'''
    password_bytes = password.encode('utf-8')
    salt = bcrypt.gensalt()
    hashed = bcrypt.hashpw(password_bytes, salt)
    return hashed.decode('utf-8')

def verify_password(password: str, hash: str):
    '''verifying password authenticity'''
    password_bytes = password.encode('utf-8')
    hash_bytes = hash.encode('utf-8')
    return bcrypt.checkpw(password_bytes, hash_bytes)

def create_access_token(username: str) -> str:
    '''generates secure jwt session token'''
    expire = datetime.now(timezone.utc) + timedelta(hours=72)
    payload = {'sub': username, 'exp': expire}

    encoded_jwt = jwt.encode(payload, SECRET_KEY, algorithm=ALGORITHM) #type: ignore
    return encoded_jwt

def verify_access_token(token: str) -> str | None:
    '''verifies token authenticity'''
    try:
        payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM]) #type: ignore
        username: str = payload.get('sub') #type: ignore
        if username is None:
            return None
        return username
    except jwt.PyJWTError:
        return None