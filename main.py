from fastapi import Depends, FastAPI, Form, HTTPException, Request
from cryptography.fernet import Fernet
from fastapi.responses import HTMLResponse
from sqlalchemy.orm import Session
from dotenv import load_dotenv
import uvicorn
import jinja2
import os

import models
from database import engine, get_db

models.Base.metadata.create_all(bind=engine)

template_loader = jinja2.FileSystemLoader(searchpath='templates')
template_env = jinja2.Environment(loader=template_loader, autoescape=jinja2.select_autoescape(['html', 'htm', 'xml']))

load_dotenv()

key = os.getenv("SECRET_KEY")
if key is None:
    raise RuntimeError('"SECRET KEY environmental variable is not set"')
fernet = Fernet(key)

app = FastAPI()

@app.get('/', response_class=HTMLResponse)
def home(request: Request):
    template = template_env.get_template('index.html')
    return template.render(request=request)

@app.post('/share', response_class=HTMLResponse)
def share_secret(request: Request, secret_data: str = Form(...), db: Session = Depends(get_db)):
    if not secret_data.strip():
        raise HTTPException(status_code=400, detail='Status code cannot be empty')

    encrypted_data = fernet.encrypt(secret_data.encode('utf-8'))

    db_secret = models.Secret(secret_text=encrypted_data)
    db.add(db_secret)
    db.commit()
    db.refresh(db_secret)

    base_url = str(request.base_url)
    share_link= f'{base_url}secret/{db_secret.id}'

    template = template_env.get_template('index.html')
    return template.render(request=request, share_link=share_link)

@app.get('/secret/{secret_id}', response_class=HTMLResponse)
def view_secret(request: Request, secret_id: str, db: Session = Depends(get_db)):
    db_secret = db.query(models.Secret).filter(models.Secret.id == secret_id).first()

    if not db_secret:
        template = template_env.get_template('view.html')
        return template.render(request=request, error='This secret has already been destroyed or never existed!')

    revealed_text = db_secret.secret_text
    db.delete(db_secret)
    db.commit()

    decrypted_text = fernet.decrypt(revealed_text).decode('utf-8') #type: ignore

    template = template_env.get_template('view.html')
    return template.render(request=request, secret_text=decrypted_text)

if __name__ == '__main__':
    uvicorn.run('main:app', host='127.0.0.1', port=8000, reload=True)