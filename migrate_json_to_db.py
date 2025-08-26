#migrar dados do json(clientes) para o banco de dados SQLite
import json
from database.database import SessionLocal
from database.models import Client, Group

# Caminho do JSON
JSON_FILE = "clients.json"

# Nome do grupo padrão
DEFAULT_GROUP_NAME = "antigo"

# Lê o JSON
with open(JSON_FILE, "r") as f:
    data = json.load(f)

# Inicia a sessão do banco
db = SessionLocal()

# Verifica se o grupo padrão existe
group = db.query(Group).filter_by(name=DEFAULT_GROUP_NAME).first()
if not group:
    group = Group(name=DEFAULT_GROUP_NAME)
    db.add(group)
    db.commit()
    db.refresh(group)

# Itera sobre os dados do JSON e insere os clientes
for entry in data:
    ip = entry["ip"]

    # Verifica duplicidade por IP
    if db.query(Client).filter_by(ip_address=ip).first():
        print(f"IP duplicado encontrado: {ip}, ignorando.")
        continue

    # Verifica duplicidade por nome
    if db.query(Client).filter_by(name=entry["name"]).first():
        print(f"Nome duplicado encontrado: {entry['name']}, ignorando.")
        continue

    client = Client(
        name=entry["name"],
        public_key=entry["public_key"],
        private_key=entry["private_key"],
        ip_address=ip,
        group_id=group.id
    )

    db.add(client)

# Finaliza
db.commit()
db.close()

print("Migração concluída com sucesso.")
