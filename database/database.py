
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker, declarative_base

# Cria uma engine SQLite em um arquivo local
engine = create_engine("sqlite:///database/wireguard.db", echo=True)

# Cria uma sessão para manipular o banco
SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)

# Base para os modelos (tabelas)
Base = declarative_base()
