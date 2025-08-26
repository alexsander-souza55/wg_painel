#Migrar usuários de um arquivo JSON para o banco de dados SQLite
import json
from werkzeug.security import generate_password_hash # Para hash de senhas
from database import SessionLocal
from database.models import User

def carregar_usuarios_json(caminho='/home/wagner/wg_painel/users.json'): # Atualize o caminho conforme necessário
    with open(caminho, 'r') as f:
        return json.load(f)

def migrar_usuarios_para_db():
    usuarios = carregar_usuarios_json()

    with SessionLocal() as db: # Abre uma sessão com o banco de dados
        for u in usuarios:
            username = u.get("username")
            password = u.get("password")

            if not username or not password:
                continue

            if db.query(User).filter_by(username=username).first():
                print(f"Usuário '{username}' já existe. Pulando.")
                continue

            user = User(
                username=username,
                password=generate_password_hash(password)
            )
            db.add(user)

        db.commit()
    print("Migração concluída com sucesso.")

if __name__ == "__main__":
    migrar_usuarios_para_db()
# Importa o Flask e outras dependências necessárias
from flask import Flask, request, jsonify   