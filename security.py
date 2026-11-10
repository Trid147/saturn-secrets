import bcrypt
from dotenv import load_dotenv
import jwt
import os
import random
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

def generate_math_captcha() -> tuple[str, str]:
    '''generates a random math question'''
    num1 = random.randint(1, 15)
    num2 = random.randint(1, 15)
    question = f'What is {num1}+{num2}?'
    answer = str(num1+num2)

    expire = datetime.now(timezone.utc) + timedelta(minutes=5)
    payload = {'captcha_ans': answer, 'exp': expire}
    signed_token = jwt.encode(payload, SECRET_KEY, algorithm=ALGORITHM) #type: ignore

    return question, signed_token

def verify_math_captcha(user_answer: str, signed_token: str | None) -> bool:
    '''checks the user_input and signed_token sameness'''
    if not user_answer or not signed_token:
        return False
    try:
        payload = jwt.decode(signed_token, SECRET_KEY, algorithms=ALGORITHM) #type: ignore
        expected_answer = payload.get('captcha_ans')
        return user_answer.strip() == expected_answer
    except jwt.PyJWTError:
        return False