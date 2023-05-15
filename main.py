from database import *
from sqlalchemy.orm import Session

from datetime import datetime, timedelta
from typing import Dict, Optional
from fastapi import Depends, FastAPI, HTTPException, status, Body
from pydantic import BaseModel

from fastapi.security import  OAuth2PasswordBearer, OAuth2PasswordRequestForm
from jose import JWTError, jwt
from passlib.context import CryptContext

from fastapi.responses import JSONResponse

Base.metadata.create_all(bind=engine)

SECRET_KEY = "09d25e094faa6ca2556c818166b9a9563b93f7099f6f0f4caa6cf63b88e8d3e7"
ALGORITHM = "HS256"
ACCESS_TOKEN_EXPIRE_MINUTES = 30

class Token(BaseModel):
    access_token: str
    token_type: str
    
class TokenData(BaseModel):
    username: Optional[str] = None
    
class Person(BaseModel):
    username: str
    
    class Config:
        orm_mode = True
    
pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")
oauth2_scheme = OAuth2PasswordBearer(tokenUrl="token")

app = FastAPI()

def get_db():
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()

def verify_password(plain_password, hashed_password):
    'Метод верификации пароля'
    return pwd_context.verify(plain_password, hashed_password)

def get_password_hash(password):
    'Метод хеширования пароля'
    return pwd_context.hash(password)

def get_user(db, username: str):
    'Метод поиска пользователя в базе данных'
    user = db.query(User).filter(User.name == username).first()
    return user

def authenticate_user(username: str, password: str, db):
    'Аутентификация пользователя'
    user = get_user(db, username)
    if not user:
        return False
    if not verify_password(password, user.hashed_password):
        return False
    return user

def create_access_token(data: dict, expires_delta: Optional[timedelta] = None):
    'Создание токена доступа'
    to_encode = data.copy()
    if expires_delta:
        expire = datetime.utcnow() + expires_delta
    else:
        expire = datetime.utcnow() + timedelta(minutes=15)
    to_encode.update({"exp": expire})
    encoded_jwt = jwt.encode(to_encode, SECRET_KEY, algorithm=ALGORITHM)
    return encoded_jwt

async def get_current_user(token: str = Depends(oauth2_scheme), db: Session = Depends(get_db)):
    'Получение текущего пользователя'
    credentials_exception = HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail="Could not validate credentials",
        headers={"WWW-Authenticate": "Bearer"},
    )
    try:
        payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
        username: str = payload.get("sub")
        if username is None:
            raise credentials_exception
        token_data = TokenData(username=username)
    except JWTError:
        raise credentials_exception
    user = get_user(db, username=token_data.username)
    if user is None:
        raise credentials_exception
    elif user is not None:
        user.token = token
    return user

@app.post("/register")
def create_person(data = Body(...,
        example={
            "name": "Foo",
            "password": "",    
        },
        ), 
        db: Session = Depends(get_db)):
    'Метод создания нового пользователя'
    password = get_password_hash(data["password"])
    user = User(name=data["name"], hashed_password=password)
    db.add(user)
    db.commit()
    db.refresh(user)
    return {"message": "Пользователь создан"}

@app.post("/token", response_model=Token)
async def login_for_access_token(form_data: OAuth2PasswordRequestForm = Depends(), 
                                 db: Session = Depends(get_db)):
    'Проверка авторизации пользователя и получения токена'
    user = authenticate_user(form_data.username, form_data.password, db)
    if not user:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Incorrect username or password",
            headers={"WWW-Authenticate": "Bearer"},
        )
    access_token_expires = timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES)
    access_token = create_access_token(
        data={"sub": user.name}, expires_delta=access_token_expires
    )
    return {"access_token": access_token, "token_type": "bearer"}

@app.post('/task')
async def create_task(task: str,
                      db: Session = Depends(get_db), 
                      current_user: Person = Depends(get_current_user)):
    'Метод создания новой записи'
    record = User_records(record=task, user=current_user.id)
    db.add(record)
    db.commit()
    db.refresh(record)
    return {"message": "Запись создана"}
    
@app.get('/task')
async def task_get_all(db: Session = Depends(get_db), 
                       token: str = Depends(oauth2_scheme)):
    'Метод получения всех записей'
    records = db.query(User_records).all()
    if records == None: 
        result = { "message": "Запись не найдена"}
    else:
        result = records
    return result

@app.get('/tasks/{task_id}')
async def task_get(task_id: int, 
                   db: Session = Depends(get_db),
                   token: str = Depends(oauth2_scheme)):
    'Метод получения записи по id'
    record = db.query(User_records).filter(User_records.id == task_id).first()
    if record == None: 
        result = { "message": "Запись не найдена"}
    else:
        result = record
    return result

@app.put('/tasks/{task_id}')
async def task_put(task_id: int,
                   new_task: str,
                   db: Session = Depends(get_db),
                   token: str = Depends(oauth2_scheme)):
    'Метод изменения записи по id'
    record = db.query(User_records).filter(User_records.id == task_id).first()
    if record == None:
        return JSONResponse( status_code=404, content={ "message": "Запись не найдена"})
    record.record = new_task
    db.commit()
    db.refresh(record)
    return {'message': 'Запись обновлена'}
    
@app.delete('/tasks/{task_id}')
async def task_delete(task_id: int,
                      db: Session = Depends(get_db),
                      token: str = Depends(oauth2_scheme)):
    'Метод удаления записи'
    record = db.query(User_records).filter(User_records.id == task_id).first()
    if record == None:
        return JSONResponse( status_code=404, content={ "message": "Запись не найдена"})
    db.delete(record)  # удаляем объект
    db.commit() 
    return { "message": "Запись удалена"}