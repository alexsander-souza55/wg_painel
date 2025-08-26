from database import SessionLocal # Importa a sessão do banco de dados  
from database.models import Group, Client # Importa os modelos do banco de dados

# Inicia a sessão
session = SessionLocal()

# Cria um grupo
grupo_teste = Group(name="TI")
session.add(grupo_teste)
session.commit()

# Cria um cliente e associa ao grupo
cliente = Client(
    name="Cliente1",
    public_key="chave_pub_exemplo",
    ip_address="10.0.0.2",
    group=grupo_teste
)
session.add(cliente)
session.commit()

session.close()
