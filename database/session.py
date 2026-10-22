from sqlalchemy.orm import sessionmaker
from database.connection import engine

session_factory = sessionmaker(bind = engine)
