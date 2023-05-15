from sqlalchemy import create_engine
from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy.orm import sessionmaker
from sqlalchemy import  Column, Integer, String, ForeignKey

#Работа с БД

SQLALCHEMY_DATABASE_URL = "postgresql://postgres:1qazxcvb@host.docker.internal:5432/postgres"

engine = create_engine(
    SQLALCHEMY_DATABASE_URL
)

Base = declarative_base()

class User(Base):
    'Таблица хранения пользователей'
    __tablename__ = "users"
 
    id = Column(Integer, primary_key=True, index=True)
    name = Column(String, unique=True)
    hashed_password = Column(String)
    
class User_records(Base):
    'Таблица хранения истории запросов'
    __tablename__ = "records"
    
    id = Column(Integer, primary_key=True, index=True)
    record = Column(String)
    user = Column(Integer, ForeignKey('users.id', ondelete='CASCADE'))
        
SessionLocal = sessionmaker(autoflush=False, bind=engine)