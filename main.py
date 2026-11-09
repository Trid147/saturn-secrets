from datetime import timedelta, datetime, timezone
from typing import Literal
from fastapi import Depends, FastAPI, Form, HTTPException, Request
from cryptography.fernet import Fernet
from fastapi.responses import HTMLResponse, RedirectResponse
from sqlalchemy import DateTime
from sqlalchemy.orm import Session
from dotenv import load_dotenv
from sqlalchemy.sql.functions import now
import uvicorn
import jinja2
import os

import models
from database import engine, get_db
from security import hash_password, verify_password, create_access_token, verify_access_token

models.Base.metadata.create_all(bind=engine)

template_loader = jinja2.FileSystemLoader(searchpath='templates')
template_env = jinja2.Environment(loader=template_loader, autoescape=jinja2.select_autoescape(['html', 'htm', 'xml']))

load_dotenv()

key = os.getenv("SECRET_KEY")
if key is None:
    raise RuntimeError('"SECRET KEY environmental variable is not set"')
fernet = Fernet(key)

app = FastAPI()

def is_auth(request: Request):
    token = request.cookies.get('session_token')
    username = verify_access_token(token) if token else None
    is_auth = True if username else False
    return is_auth

@app.get('/', response_class=HTMLResponse)
def home(request: Request):
    authorized = is_auth(request)

    template = template_env.get_template('index.html')
    return template.render(request=request, authorized=authorized)

@app.post('/share', response_class=HTMLResponse)
def share_secret(
    request: Request,
    secret_data: str = Form(...),
    lifespan: Literal['burn', '1h', '24h', '7d'] = Form(...),
    whitelist: str | None = Form(default=None),
    blacklist: str | None = Form(default=None),
    db: Session = Depends(get_db)
):
    if not secret_data.strip():
        raise HTTPException(status_code=400, detail='Status code cannot be empty')

    durations = {'1h': timedelta(hours=1), '24h': timedelta(hours=24), '7d': timedelta(days=7)}
    expires_at = (None if lifespan == 'burn' else datetime.now(timezone.utc) + durations[lifespan])

    authorized = is_auth(request)

    token = request.cookies.get('session_token')
    username = verify_access_token(token) if token else None

    encrypted_data = fernet.encrypt(secret_data.encode('utf-8'))

    db_secret = models.Secret(secret_text=encrypted_data, owner_username=username, expires_at=expires_at, whitelist=whitelist, blacklist=blacklist)
    db.add(db_secret)
    db.commit()
    db.refresh(db_secret)

    base_url = str(request.base_url)
    share_link= f'{base_url}secret/{db_secret.id}'

    template = template_env.get_template('index.html')
    return template.render(request=request, share_link=share_link, authorized=authorized)

@app.get('/secret/{secret_id}', response_class=HTMLResponse)
def view_secret(request: Request, secret_id: str, db: Session = Depends(get_db)):
    authorized = is_auth(request)

    db_secret = db.query(models.Secret).filter(models.Secret.id == secret_id).first()

    if not db_secret:
        template = template_env.get_template('view.html')
        return template.render(request=request, error='This secret has already been destroyed or never existed!', authorized=authorized)

    expire_time = db_secret.expires_at

    if expire_time is not None:
        if expire_time.tzinfo is None:
            expire_time = expire_time.replace(tzinfo=timezone.utc)

        if expire_time <= datetime.now(timezone.utc): #type: ignore
            db.delete(db_secret)
            db.commit()
            template = template_env.get_template('view.html')
            return template.render(request=request, error='This secret has expired.', authorized=authorized)

    whitelist = (db_secret.whitelist or '').strip()
    blacklist = (db_secret.blacklist or '').strip()

    if whitelist and blacklist:
        raise HTTPException(status_code=400, detail='Cannot set both a whitelist and a blacklist at the same time!')

    token = request.cookies.get('session_token')
    username = verify_access_token(token) if token else None

    allowed = True

    if whitelist is not None:
        allowed_usernames = [u.strip() for u in db_secret.whitelist.split(',') if u.strip()]
        if not username or username not in allowed_usernames:
            allowed = False

    elif blacklist is not None:
        disallowed_usernames = [u.strip() for u in db_secret.blacklist.split(',') if u.strip()]
        if username and username in disallowed_usernames:
            allowed = False

    if not allowed:
        template = template_env.get_template('view.html')
        return template.render(request=request, error='Access denied.', authorized=authorized)

    revealed_text = db_secret.secret_text
    db.delete(db_secret)
    db.commit()

    decrypted_text = fernet.decrypt(revealed_text).decode('utf-8') #type: ignore

    template = template_env.get_template('view.html')
    return template.render(request=request, secret_text=decrypted_text, authorized=authorized)

@app.get('/register', response_class=HTMLResponse)
def auth_register(request: Request):
    authorized = is_auth(request)

    if authorized:
        response = RedirectResponse(url='/dashboard', status_code=303)
        return response
        
    template = template_env.get_template('auth/register.html')
    return template.render(request=request)

@app.get('/login', response_class=HTMLResponse)
def auth_login(request: Request):
    authorized = is_auth(request)

    if authorized:
        response = RedirectResponse(url='/dashboard', status_code=303)
        return response

    template = template_env.get_template('auth/login.html')
    return template.render(request=request)

@app.post('/register')
def handle_registration(request: Request, username: str = Form(...), password: str = Form(...), password_repeat: str = Form(...), db: Session = Depends(get_db)):
    if password != password_repeat:
        template = template_env.get_template('auth/register.html')
        return HTMLResponse(content=template.render(request=request, error='Passwords do not match!'))

    if len(password) < 8:
        template = template_env.get_template('auth/register.html') 
        return HTMLResponse(content=template.render(request=request, error='Password must contain at least 8 characters!'))

    if not username.strip():
        template = template_env.get_template('auth/register.html')
        return HTMLResponse(content=template.render(request=request, error='Username can not be blank!'))

    existing_user = db.query(models.User).filter(models.User.username == username).first()
    if existing_user:
        template = template_env.get_template('auth/register.html')
        return HTMLResponse(content=template.render(request=request, error='This user is already registered!'))

    hashed_password = hash_password(password)

    new_user = models.User(username=username, hashed_password=hashed_password)
    db.add(new_user)
    db.commit()
    db.refresh(new_user)

    template = template_env.get_template('auth/login.html')
    return HTMLResponse(content=template.render(request=request, success_message='Account created successsfully! Please log in.'))

@app.post('/login', response_class=HTMLResponse)
def handle_login(request: Request, username: str = Form(...), password: str = Form(...), db: Session = Depends(get_db)):
    if not username.strip():
        template = template_env.get_template('auth/login.html')
        return HTMLResponse(content=template.render(request=request, error='Username can not be blank!'))

    existing_user = db.query(models.User).filter(models.User.username == username).first()
    if not existing_user:
        template = template_env.get_template('auth/login.html')
        return HTMLResponse(content=template.render(request=request, error='This user is not registered!'))

    if not verify_password(password, existing_user.hashed_password): #type: ignore
        template = template_env.get_template('auth/login.html')
        return HTMLResponse(content=template.render(request=request, error='Wrong password! Please, try again.'))

    token = create_access_token(username)

    response = RedirectResponse(url='/dashboard', status_code=303)

    response.set_cookie(key='session_token', value=token, httponly=True, secure=False, samesite='lax')

    return response

@app.get('/dashboard', response_class=HTMLResponse)
def dashboard(request: Request):
    authorized = is_auth(request)

    if not authorized:
        template = template_env.get_template('auth/login.html')
        return template.render(request=request, error='Unathorized access. Please log in first.')

    token = request.cookies.get('session_token')
    username = verify_access_token(token) if token else None

    template = template_env.get_template('dashboard/menu.html')
    return template.render(request=request, current_user=username, authorized=authorized)

@app.get('/logout')
def logout(request: Request):
    response = RedirectResponse('/', status_code=303)
    response.delete_cookie('session_token')
    return response

@app.get('/dashboard/secrets', response_class=HTMLResponse)
def dashboard_secrets(request: Request):
    authorized = is_auth(request)

    if not authorized:
        template = template_env.get_template('auth/login.html')
        return template.render(request=request, error='Unathorized access. Please log in first.')

    active_secrets = []

    template = template_env.get_template('dashboard/secrets.html')
    return template.render(request=request, authorized=authorized, secrets=active_secrets)

@app.get('/dashboard/account', response_class=HTMLResponse)
def dashboard_account(request: Request):
    authorized = is_auth(request)

    if not authorized:
        template = template_env.get_template('auth/login.html')
        return template.render(request=request, error='Unathorized access. Please log in first.')

    token = request.cookies.get('session_token')
    username = verify_access_token(token) if token else None

    template = template_env.get_template('dashboard/account.html')
    return template.render(request=request, current_user=username, authorized=authorized)

@app.get('/dashboard/settings', response_class=HTMLResponse)
def dashboard_settings(request: Request):
    authorized = is_auth(request)

    if not authorized:
        template = template_env.get_template('auth/login.html')
        return template.render(request=request, error='Unathorized access. Please log in first.')

    template = template_env.get_template('dashboard/settings.html')
    return template.render(request=request, authorized=authorized)

@app.get('/dashboard/change-password')
def dashboard_password(request: Request):
    authorized = is_auth(request)

    if not authorized:
        template = template_env.get_template('auth/login.html')
        return HTMLResponse(content=template.render(request=request, error='Unathorized access. Please log in first.'))

    template = template_env.get_template('dashboard/password.html')
    return HTMLResponse(content=template.render(request=request, authorized=authorized))

@app.post('/dashboard/change-password', response_class=HTMLResponse)
def handle_change_password(request: Request, password: str = Form(...), new_password: str = Form(...), new_password_repeat: str = Form(...), db: Session = Depends(get_db)):
    template = template_env.get_template('dashboard/password.html')

    token = request.cookies.get('session_token')
    username = verify_access_token(token) if token else None
    
    if not username:
        login_temp = template_env.get_template('auth/login.html')
        return HTMLResponse(content=login_temp.render(request=request, error='Something went wrong. Log in again, please.'))

    if new_password != new_password_repeat:
        return HTMLResponse(content=template.render(request=request, authorized=True, error='New passwords do not match!'))
    
    if len(new_password) < 8:
        return HTMLResponse(content=template.render(request=request, authorized=True, error='New password must contain at least 8 characters!'))

    existing_user = db.query(models.User).filter(models.User.username == username).first()
    if not verify_password(password, existing_user.hashed_password): #type: ignore
        return HTMLResponse(content=template.render(request=request, authorized=True, error='Wrong current password! Please try again.'))

    existing_user.hashed_password = hash_password(new_password) #type: ignore
    return HTMLResponse(content=template.render(request=request, authorized=True, success_message='Password changed successfully.'))

if __name__ == '__main__':
    uvicorn.run('main:app', host='127.0.0.1', port=8000, reload=True)