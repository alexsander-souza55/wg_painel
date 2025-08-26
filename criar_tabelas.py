from database import Base, engine # ou: from database import Base, engine
from database.models import User  # ou: from database.models import User

# Cria todas as tabelas definidas pelos modelos
Base.metadata.create_all(bind=engine)
print("Tabelas criadas com sucesso.")
# Se você quiser criar apenas uma tabela específica, pode usar:
# Base.metadata.create_all(bind=engine, tables=[User.__table__])    