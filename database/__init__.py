#arquivo de inicialização do banco de dados database/__init__.py 
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker, declarative_base
import os


BASE_DIR = os.path.abspath(os.path.dirname(__file__)) # Diretório atual (database)
DB_PATH = os.path.join(BASE_DIR, 'wireguard.db') # Caminho completo para o banco de dados
DATABASE_URL = f"sqlite:///{DB_PATH}" # URL do banco de dados SQLite

engine = create_engine(DATABASE_URL, connect_args={"check_same_thread": False}) # Necessário para SQLite com múltiplas threads
SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine) # Sessão para operações no banco
Base = declarative_base()
# Cria as tabelas, se não existirem
Base.metadata.create_all(engine)


