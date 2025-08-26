# init_db.py

from database.database import engine
from database import models

# Cria todas as tabelas
models.Base.metadata.create_all(bind=engine)

print("Banco de dados criado com sucesso.")
