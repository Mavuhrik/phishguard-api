from sqlalchemy import create_engine
from database.models import Base
DATABASE_URL = "sqlite:///phishguard.db"
engine = create_engine(DATABASE_URL)

Base.metadata.create_all(engine)

