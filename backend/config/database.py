from sqlalchemy import create_engine
from sqlalchemy.orm import declarative_base
from sqlalchemy.orm import sessionmaker

# Example configuration for MySQL
# Replace user, password, host, and db_name with actual values
SQLALCHEMY_DATABASE_URL = "mysql+pymysql://user:password@localhost:3306/db_name"

engine = create_engine(SQLALCHEMY_DATABASE_URL)

SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)

Base = declarative_base()

def get_db():
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()
