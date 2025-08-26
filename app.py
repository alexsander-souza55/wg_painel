# app.py
from typing import cast
from pathlib import Path
#from ipaddress import ip_address
from flask import Flask, render_template, request, redirect, url_for, jsonify, current_app
import subprocess
import os
import json
from sqlalchemy import select, and_
import re
import socket
import requests
from datetime import datetime, timedelta 
import time
from flask import session, flash
from functools import wraps
from database import SessionLocal
from database import Base
from database.models import Client, Group  # <-- adicione Client aqui se ainda não tiver
from database.models import User  # Certifique-se que você tem um modelo User definido
from werkzeug.security import generate_password_hash
from werkzeug.security import check_password_hash
from typing import Optional



app = Flask(__name__) 
app.config['DEBUG'] = False  # Desativa o modo de depuração


#db = SessionLocal()     # Iniciando o db  
# Verifica se o grupo padrão existe

# Busca dados de um cliente pelo nome


def get_client_by_name_db(client_name: str) -> Optional[Client]:
    with SessionLocal() as db:
        return db.query(Client).filter(Client.name == client_name).first()
    
# Função para carregar o arquivo de configuração
def load_config(filename):       
    config = {}
    try:    # Tenta abrir o arquivo de configuração
        with open(filename, 'r') as f:
            for line in f:  # Lê cada linha do arquivo
                line = line.strip()
                if line and not line.startswith('#') and '=' in line: # Verifica se a linha não está vazia, não é um comentário e contém um '='
                    key, value = line.split('=', 1)
                    config[key.strip()] = value.strip().strip('"').strip("'")
    except FileNotFoundError:   # Se o arquivo não for encontrado, exibe uma mensagem de erro
        print(f"[ERRO] Arquivo de configuração '{filename}' não encontrado.")
        exit(1)
    except Exception as e:  # Se ocorrer qualquer outro erro, exibe uma mensagem de erro
        print(f"[ERRO] Falha ao carregar '{filename}': {e}")
        exit(1)
    return config

conf = load_config('/home/wagner/wg_painel/config.conf')    # Carrega o arquivo de configuração
# Verifica se as chaves necessárias estão presentes no arquivo de configuração
try:
    WG_INTERFACE = conf['WG_INTERFACE']
    ENDPOINT = conf['ENDPOINT']
    PORT = int(conf['PORT'])
    PREFIXIP = conf['PREFIXIP']
    MASCIP = int(conf['MASCIP'])
    PREFIX_PORT = conf['PREFIX_PORT']
    ENDPOINT_PORT = conf['ENDPOINT_PORT']
    CAMINHO_DB = conf['CAMINHO_DB']
    print(CAMINHO_DB)
except KeyError as e:
    print(f"[ERRO] Configuração faltando: {e}")
    exit(1)
except ValueError as e:
    print(f"[ERRO] Erro de tipo em configuração: {e}")
    exit(1)

WG_HELPER_SCRIPT: Path = Path('/usr/local/bin/wg_helper.sh')
# Necessário para usar sessões
app.secret_key =  os.environ.get('FLASK_SECRET_KEY', 'change-me')  # Certifique-se de definir uma chave secreta forte em produção   

@app.route('/login', methods=['GET', 'POST']) 
def login(): # Função para autenticar usuários
    if request.method == 'POST': # Se o método for POST, processa o formulário
        username = request.form.get('username', '').strip()
        password = request.form.get('password', '').strip()

        print(f"Usuário informado: {username}")

        with SessionLocal() as db: # Inicia uma sessão do banco de dados
            user = db.query(User).filter_by(username=username).first()
            print(f"Usuário encontrado no banco: {user}")


        # Verifica se o usuário existe e se a senha está correta
        if user and check_password_hash(user.password, password):
                print("Login validado com sucesso")
                session['user'] = username
                flash('Login bem-sucedido!', 'success')
                return redirect(url_for('index'))
        else:
                print("Falha na autenticação: senha incorreta ou usuário não encontrado")
                flash('Usuário ou senha inválidos.', 'danger')
                return redirect(url_for('login'))

    return render_template('login.html')


@app.route('/grupos')
def listar_grupos(): #Exibe uma página com todos os grupos cadastrados no sistema.
    db = SessionLocal()
    grupos = db.query(Group).all() # Obtém todos os grupos do banco de dados
    if not grupos: # Se não houver grupos, exibe uma mensagem
        flash("Nenhum grupo cadastrado.", "info")
        grupos = []  # Garante que a variável grupos seja uma lista vazia
    else:
        flash(f"{len(grupos)} grupo(s) encontrado(s).", "success")  # Exibe a quantidade de grupos encontrados
    # Fecha a sessão do banco de dados
    db.close()
    return render_template('grupos.html', grupos=grupos)

@app.route("/grupos/<int:grupo_id>/clientes")
def listar_clientes_por_grupo(grupo_id): # Exibe uma lista de clientes pertencentes a um grupo específico.
    db = SessionLocal()
    grupo = db.query(Group).filter_by(id=grupo_id).first() # Obtém o grupo pelo ID fornecido na URL
    if not grupo:
        return "Grupo não encontrado", 404

    clientes = grupo.clients  # Isso funciona se você tem o relacionamento definido no modelo Group
    db.close()
    return render_template("clientes_por_grupo.html", grupo=grupo, clients=clientes) # Renderiza o template com o grupo e seus clientes



@app.route('/usuarios/novo', methods=['GET', 'POST'])
def novo_usuario(): # Função para adicionar um novo usuário
    if request.method == 'POST': # Se o método for POST, processa o formulário
        print("Processando novo usuário...")
        # Obtém os dados do formulário
        # Usando request.form.get() para evitar KeyError se o campo não existir
        # Usando strip() para remover espaços em branco desnecessários
        print("Coletando dados do formulário...")
         # Coleta os dados do formulário
         # Usando request.form.get() para evitar KeyError se o campo não existir
         # Usando strip() para remover espaços em branco desnecessários
        username = request.form.get('username', '').strip()
        password = request.form.get('password', '').strip()

        if not username or not password: # Verifica se o nome de usuário e a senha foram fornecidos
            flash('Usuário e senha são obrigatórios.', 'danger')
            return redirect(url_for('novo_usuario'))

        with SessionLocal() as db: # Inicia uma sessão do banco de dados
            if db.query(User).filter_by(username=username).first(): # Verifica se o usuário já existe
                flash('Nome de usuário já existe.', 'danger')
                return redirect(url_for('novo_usuario'))

            novo_user = User(username=username, password=generate_password_hash(password))  # Lembre de usar hash se for produção
            db.add(novo_user)
            db.commit()
            flash('Usuário criado com sucesso.', 'success')
            return redirect(url_for('index'))

    return render_template('novo_usuario.html')



@app.route("/novo_cliente", methods=["GET", "POST"])
def novo_cliente():
    # Exibe um formulário para adicionar um novo cliente a um grupo específico.
    # Se o método for POST, processa o formulário e adiciona o cliente.
    # Se for GET, apenas exibe o formulário.

    if request.method == "POST":
        db_session = SessionLocal()
        try:
            print("Processando novo cliente...")
            # --- Coleta de Dados do Formulário ---
            # Obtém os dados do formulário
            # Usando request.form.get() para evitar KeyError se o campo não existir
            # Usando strip() para remover espaços em branco desnecessários
            name = request.form.get("name", "").strip() 
            group_id_str = request.form.get("group_id", "").strip()
            print(group_id_str)
            #group_id_str = str(request.form.get("group_id"))

            # --- Validações ---
            if not name:
                print("Nome do cliente não fornecido.")
                flash("O nome do cliente é obrigatório.", "danger")
                return redirect(url_for("novo_cliente"))

            group_id = int(group_id_str)
            print(f"ID do grupo selecionado: {group_id}")
            grupo = db_session.get(Group, group_id)
            print(f"Grupo encontrado: {grupo}")
            # Verifica se o grupo existe
            # Se o grupo não for encontrado, retorna uma mensagem de erro
            # e redireciona para a página de criação de cliente
            if not grupo:
                flash("Grupo selecionado é inválido.", "danger")
                return redirect(url_for("novo_cliente"))

            # VERIFICAÇÃO ADICIONAL: Cliente com este nome já existe?
            existing_client = db_session.query(Client).filter_by(name=name).first()
            print(f"Cliente existente: {existing_client}")
            # Se já existir um cliente com o mesmo nome, exibe uma mensagem de erro
            # e redireciona para a página de criação de cliente
            # Isso evita duplicação de clientes com o mesmo nome
            if existing_client:
                flash(f'Erro: Cliente com o nome "{name}" já existe.', 'danger')
                return redirect(url_for("novo_cliente"))

            # --- Lógica de Criação do Cliente ---
            # Gera IP baseado no último cliente do BANCO DE DADOS
            # Lista de IPs já usados no banco
            used_ips = {client.ip_address for client in db_session.query(Client).all()}

            # Tenta encontrar um IP livre entre .2 e .254
            for i in range(2, 255):
                ip_candidate = f"{PREFIXIP}{i}"
                if ip_candidate not in used_ips:
                    ip_address = ip_candidate
                    break
            else:
                flash("Limite de IPs atingido.", "danger")
                return redirect(url_for("novo_cliente"))
            # Se não encontrar um IP livre, exibe uma mensagem de erro
            # e redireciona para a página de criação de cliente
            # Isso garante que cada cliente tenha um IP único
            if not ip_address:
                flash("Não foi possível gerar um IP livre para o novo cliente.", "danger")
                return redirect(url_for("novo_cliente"))

            print(f"IP gerado para o novo cliente: {ip_address}")

            private_key = subprocess.check_output(['wg', 'genkey']).decode().strip() # Gera a chave privada do cliente
            public_key = subprocess.check_output(['wg', 'pubkey'], input=private_key.encode()).decode().strip() # Gera a chave pública do cliente a partir da chave privada
            server_public_key = get_server_public_key()
            print(Client)
            new_client = Client(
                name=name,
                ip_address=ip_address,
                private_key=private_key,
                public_key=public_key,
                server_public_key=server_public_key,
                group_id=group_id
            )
            print(f"Adicionando cliente: {new_client.name}, IP: {new_client.ip_address}, Grupo ID: {new_client.group_id}")
            print(new_client)
            db_session.add(new_client)
            db_session.commit()

            subprocess.run(['sudo', WG_HELPER_SCRIPT, 'add', name, public_key, ip_address], check=True) # Adiciona o cliente ao arquivo de configuração do WireGuard
            flash(f"Cliente '{name}' adicionado com sucesso ao grupo '{grupo.name}'.", "success")
            return redirect(url_for("listar_clientes_por_grupo", grupo_id=group_id))

        except Exception as e: # Captura qualquer erro que ocorra durante o processo de adição do cliente
            print(f"Erro ao adicionar cliente: {e}")
            # Em caso de erro, desfaz as alterações no banco de dados
            db_session.rollback()
            flash(f"Ocorreu um erro ao criar o cliente: {e}", "danger")
            return redirect(url_for("novo_cliente"))
        finally: # Garante que a sessão do banco de dados seja fechada, independentemente de sucesso ou falha
            print("Fechando sessão do banco de dados.")
            # Fecha a sessão do banco de dados
            db_session.close()

    # --- Lógica para requisição GET (exibir o formulário) ---
    db_session = SessionLocal()
    grupos = db_session.query(Group).all()
    db_session.close()
    return render_template("novo_cliente.html", grupos=grupos)

@app.route("/grupos/novo", methods=["GET", "POST"])
def novo_grupo(): # Função para criar um novo grupo
    if request.method == "POST":
        nome = request.form.get("name", "").strip() # Obtém o nome do grupo do formulário, removendo espaços em branco desnecessários
        if not nome: # Verifica se o nome do grupo foi fornecido
            flash("O nome do grupo não pode estar vazio.", "error")
            return redirect(url_for("novo_grupo"))

        with SessionLocal() as db: # Inicia uma sessão do banco de dados
            # Verifica se já existe um grupo com o mesmo nome
            # Se já existir, exibe uma mensagem de erro e redireciona para a página de criação de grupo
            # Isso evita duplicação de grupos com o mesmo nome
            if db.query(Group).filter_by(name=nome).first():
                flash(f"Grupo '{nome}' já existe.", "error")
                return redirect(url_for("novo_grupo"))

            novo_grupo = Group(name=nome)
            db.add(novo_grupo)
            db.commit()
            db.refresh(novo_grupo)

        flash(f"Grupo '{nome}' criado com sucesso!", "success") 
        return redirect(url_for("listar_grupos")) # Redireciona para a lista de grupos após a criação bem-sucedida

    return render_template("novo_grupo.html")

@app.route("/grupos/<int:grupo_id>/editar", methods=["GET", "POST"])
def editar_grupo(grupo_id): # Função para editar um grupo existente
    # Obtém o grupo pelo ID fornecido na URL
    # Se o grupo não for encontrado, exibe uma mensagem de erro e redireciona para a lista de grupos
    # Se o método for POST, processa o formulário e atualiza o grupo
    # Se for GET, apenas exibe o formulário com os dados do grupo
    # Isso permite que o usuário edite o nome do grupo
    with SessionLocal() as db:
        grupo = db.get(Group, grupo_id)

        if not grupo:
            flash("Grupo não encontrado.", "error")
            return redirect(url_for("listar_grupos"))

        if request.method == "POST":
            novo_nome = request.form.get("name", "").strip()

            if not novo_nome:
                flash("O nome do grupo não pode estar vazio.", "error")
                return redirect(url_for("editar_grupo", grupo_id=grupo_id))

            if db.query(Group).filter(Group.name == novo_nome, Group.id != grupo_id).first(): # Verifica se já existe outro grupo com o mesmo nome
                # Se já existir outro grupo com o mesmo nome, exibe uma mensagem de erro
                # e redireciona para a página de edição do grupo
                # Isso evita duplicação de grupos com o mesmo nome
                flash(f"Já existe outro grupo com o nome '{novo_nome}'.", "error")
                return redirect(url_for("editar_grupo", grupo_id=grupo_id))

            grupo.name = novo_nome
            db.commit()
            flash("Grupo atualizado com sucesso!", "success")
            return redirect(url_for("listar_grupos"))

    return render_template("editar_grupo.html", grupo=grupo)


@app.route("/grupos/<int:grupo_id>/apagar", methods=["POST"])
def apagar_grupo(grupo_id):
    db = SessionLocal()

    grupo = db.query(Group).filter_by(id=grupo_id).first()
    if not grupo:
        db.close()
        flash("Grupo não encontrado.", "error")
        return redirect(url_for('listar_grupos'))

    # Verifica se o grupo possui clientes
    if grupo.clients:  # lista não vazia
        db.close()
        flash("Não é possível excluir o grupo porque ele ainda contém clientes.", "error")
        return redirect(url_for('listar_grupos'))

    # Grupo vazio, pode excluir
    db.delete(grupo)
    db.commit()
    db.close()

    flash("Grupo excluído com sucesso.", "success")
    return redirect(url_for('listar_grupos'))


@app.route("/buscar")
def buscar():
    termo = request.args.get("q", "")
    with SessionLocal() as db:
        clientes = db.query(Client).filter(Client.name.ilike(f"%{termo}%")).all()
        grupos = db.query(Group).filter(Group.name.ilike(f"%{termo}%")).all()
    return render_template("busca.html", clientes=clientes, grupos=grupos, termo=termo)

def contar_peers_conectados(peers, janela_segundos: int = 120) -> int:
    now = int(time.time())
    return sum(
        1 for p in peers
        if isinstance(p.get("raw_handshake"), int) and (now - p["raw_handshake"]) < janela_segundos
    )


def login_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if 'user' not in session:
            flash('Você precisa estar logado.', 'warning')
            return redirect(url_for('login'))
        return f(*args, **kwargs)
    return decorated_function


def load_clients() -> list[Client]:
    with SessionLocal() as db:
        return db.query(Client).all()






USERS_FILE = 'users.json'

def load_users():
    if os.path.exists(USERS_FILE):
        with open(USERS_FILE, 'r') as f:
            return json.load(f)
    return []



def format_bytes(size):
    """Format bytes into a readable string."""
    for unit in ['B', 'KiB', 'MiB', 'GiB', 'TiB']:
        if size < 1024:
            return f"{size:.2f} {unit}"
        size /= 1024
    return f"{size:.2f} PiB"

def format_timestamp(ts):
    """Format a WireGuard timestamp (epoch seconds) into human-readable or 'Inválido'."""
    try:
        ts = int(ts)
        if ts == 0:
            return "Inválido"
        dt = datetime.utcfromtimestamp(ts)
        return dt.strftime("%Y-%m-%d %H:%M:%S")
    except ValueError:
        return "Inválido"
def parse_wg_status():
    try:
        interface = "wg0"
        output = subprocess.check_output(["sudo", "wg", "show", interface, "dump"], encoding="utf-8")
        lines = output.strip().split("\n")

        # Mapeia public_key -> Client (ou só name) via DB
        with SessionLocal() as db:
            rows = db.query(Client.public_key, Client.name).all()
            public_key_to_name = {pk: nm for (pk, nm) in rows}

        peers = []
        for line in lines[1:]:
            parts = line.split('\t')
            if len(parts) >= 8:
                public_key = parts[0]
                endpoint = parts[2]
                allowed_ips = parts[3]
                latest_handshake = int(parts[4])
                rx = int(parts[5])
                tx = int(parts[6])

                if latest_handshake == 0:
                    latest_handshake_str = "Nunca"
                else:
                    diff = int(time.time()) - latest_handshake
                    minutes = diff // 60
                    seconds = diff % 60
                    latest_handshake_str = f"{minutes} min {seconds} s atrás"

                name = public_key_to_name.get(public_key, "(desconhecido)")

                peer_info = {
                    "name": name,
                    "public_key": public_key,
                    "endpoint": endpoint if endpoint != "(none)" else "Offline",
                    "allowed_ips": allowed_ips,
                    "latest_handshake": latest_handshake_str,
                    "rx": format_bytes(rx),
                    "tx": format_bytes(tx),
                    "raw_handshake": latest_handshake,
                }
                peers.append(peer_info)
        return peers, None
    except subprocess.CalledProcessError as e:
        return [], f"Erro ao executar wg show: {e}"

@app.route('/logout')
def logout():
    session.pop('user', None)
    flash('Logout realizado com sucesso.', 'info')
    return redirect(url_for('login'))


@app.route("/")
@login_required
def index():
    try:
        peers, error = parse_wg_status()
        wg_status_error = error is not None

        # Contagem de peers conectados (último handshake menor que 2 minutos)
        total_peers = len(peers)
        peers_conectados = contar_peers_conectados(peers, 120)
        peers_desconectados = total_peers - peers_conectados


        # Total de grupos
        with SessionLocal() as db:
            total_grupos = db.query(Group).count()

        return render_template("index.html",
            peers=peers,
            wg_status_error=wg_status_error,
            peers_conectados=peers_conectados,
            peers_desconectados=peers_desconectados,
            total_peers=total_peers,
            total_grupos=total_grupos
        )

    except Exception as e:
        print(f"Erro inesperado no index: {e}")
        return render_template("index.html", peers=[], wg_status_error=True)

@app.route('/wg-status')
def wg_status():
    try:
        result = subprocess.run(
            ['sudo', 'wg', 'show', 'all', 'dump'],
            capture_output=True,
            text=True,
            check=True
        )
        return jsonify({"output": result.stdout})
    except subprocess.CalledProcessError as e:
        # Retorna o erro para facilitar debug
        return jsonify({"error": str(e), "stderr": e.stderr}), 500
    except Exception as e:
        return jsonify({"error": str(e)}), 500


# Rota para adicionar um novo cliente
@app.route('/add', methods=['POST'])
def add():
    name = request.form['name'].strip()
    if not name:
        flash("Nome é obrigatório.", "danger")
        return redirect(url_for('index'))

    with SessionLocal() as db:
        # Verifica duplicado
        if db.query(Client).filter(Client.name == name).first():
            flash(f'Cliente "{name}" já existe.', 'danger')
            return redirect(url_for('index'))

        # IP: gere a partir do DB (similar ao novo_cliente)
        used_ips = set(
            db.scalars(
                select(Client.ip_address).where(
                    and_(Client.ip_address.is_not(None), Client.ip_address != "")
             )       
             ).all()
)
        client_ip = None
        for i in range(2, 255):
            ip_candidate = f"{PREFIXIP}{i}"
            if ip_candidate not in used_ips:
                client_ip = ip_candidate
                break
        if not client_ip:
            flash("Sem IP livre.", "danger")
            return redirect(url_for('index'))

        private_key = subprocess.check_output(['wg', 'genkey']).decode().strip()
        public_key = subprocess.check_output(['wg', 'pubkey'], input=private_key.encode()).decode().strip()
        server_public_key = get_server_public_key()

        client = Client(
            name=name,
            ip_address=client_ip,
            private_key=private_key,
            public_key=public_key,
            server_public_key=server_public_key,
            # group_id=... (opcional)
        )
        db.add(client)
        db.commit()

        # Script
        subprocess.run(['sudo', os.fspath(WG_HELPER_SCRIPT), 'add', name, public_key, client_ip], check=True)


    flash(f'Cliente "{name}" adicionado com sucesso.', 'success')
    return redirect(url_for('index'))

# Rota para deletar um cliente
@app.route('/delete/<int:client_id>')
@login_required
def delete(client_id: int):
    # Use contexto para fechar a sessão automaticamente
    with SessionLocal() as db:
        client = db.query(Client).filter(Client.id == client_id).first()
        if not client:
            flash('Cliente não encontrado.', 'danger')
            return redirect(url_for('index'))

        try:
            # Monte o comando com tipos garantidos
            cmd = [
                'sudo',
                os.fspath(WG_HELPER_SCRIPT),   # garante str/path correto
                'remove',
                cast(str, client.name),        # se o modelo já usa Mapped[str], dá pra remover o cast
            ]

            # Rodar o helper; text=True para stdout/stderr como str
            completed = subprocess.run(cmd, check=True, text=True, capture_output=True)
            current_app.logger.info("wg-helper remove OK: %s", completed.stdout.strip())

            db.delete(client)
            db.commit()
            flash(f'Cliente {client.name} removido com sucesso!', 'success')

        except subprocess.CalledProcessError as e:
            db.rollback()
            # Mostra stderr do script para facilitar o debug
            err = (e.stderr or '').strip()
            current_app.logger.error("wg-helper falhou: returncode=%s stderr=%s", e.returncode, err)
            flash(f'Erro ao remover o cliente no WireGuard: {err or e}', 'danger')

        except Exception as e:
            db.rollback()
            current_app.logger.exception("Erro ao remover cliente do banco")
            flash(f'Erro ao remover o cliente: {e}', 'danger')

    return redirect(url_for('index'))
# Busca informações de um cliente diretamente no arquivo de configuração do WireGuard

# Busca informações de um cliente diretamente no arquivo de configuração do WireGuard
def get_client_info_from_conf(client_name):
    with open('/etc/wireguard/wg0.conf', 'r') as f:
        content = f.read()

    # Expressão regular para extrair bloco de peer com base no nome
    pattern = rf"# {re.escape(client_name)}\n\[Peer\]\nPublicKey = (.+?)\nAllowedIPs = (.+?)/32"
    match = re.search(pattern, content)
    if match:
        return {
            "public_key": match.group(1),
            "ip": match.group(2)
        }
    return None

# Lê a chave pública do servidor a partir de um arquivo
def get_server_public_key():
    try:
        with open('/etc/wireguard/server_public.key', 'r') as f:
            key = f.read().strip()
            return key
    except Exception as e:
        print(f"Erro ao ler a chave pública: {e}")
        return "Chave não encontrada"

# Lê a chave privada de um cliente específico
def get_client_private_key(name):
    key_path = f"/etc/wireguard/clients/{name}_private.key"
    try:
        with open(key_path, 'r') as f:
            return f.read().strip()
    except:
        return "(Chave privada não encontrada)"




# Obtém IP público da máquina (usando socket UDP)
def get_public_ip():
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.connect(("8.8.8.8", 80))
        ip = s.getsockname()[0]
        s.close()
        return ip
    except:
        return "IP-desconhecido"

# Lê a porta configurada no wg0.conf
def get_server_port():
    try:
        with open('/etc/wireguard/wg0.conf', 'r') as f:
            content = f.read()
        match = re.search(r"ListenPort\s*=\s*(\d+)", content)
        if match:
            return match.group(1)
        return "51820"
    except:
        return "51820"

# Obtém o endpoint público do servidor (domínio ou IP + porta)
def get_server_endpoint():
    try:
        public_ip = requests.get('https://api.ipify.org').text.strip()
        try:
            domain = socket.gethostbyaddr(public_ip)[0]
        except socket.herror:
            domain = public_ip
        port = get_server_port()
        return f"{domain}:{port}"
    except Exception as e:
        print(f"[Erro] ao obter endpoint dinâmico: {e}")
        return f"erro-obtendo-endpoint:{get_server_port()}"


# Rota para exibir a configuração do cliente em formato MikroTik
@app.route('/config-mk/<client_name>')
def config_mk(client_name):
    client = get_client_by_name_db(client_name)
    if not client:
        return "Cliente não encontrado", 404

    client_id = client.id
    server_pub_key = get_server_public_key()
    endpoint = ENDPOINT
    endpoint_port = ENDPOINT_PORT
    port_conf = int(PREFIX_PORT) + int(client_id)

    mikrotik_config = f"""
/interface wireguard
add listen-port={port_conf} name=wg-{client.name} private-key="{client.private_key}"
/interface wireguard peers
add interface=wg-{client.name} public-key="{server_pub_key}" endpoint-address={endpoint} endpoint-port={endpoint_port} allowed-address=0.0.0.0/0
/ip address
add address={client.ip_address}/24 interface=wg-{client.name}
""".strip()

    return render_template(
        "config_mk.html",
        client_name=client.name,
        client_ip=client.ip_address,
        client_pub_key=client.public_key,
        client_priv_key=client.private_key,
        server_pub_key=server_pub_key,
        endpoint=endpoint,
        port_conf=port_conf,
        endpoint_port=endpoint_port,
        mikrotik_config=mikrotik_config
    )


# Rota para exibir estatísticas de conexão de um cliente
@app.route('/conexoes/<client_name>')
def conexoes(client_name):
    client = get_client_by_name_db(client_name)
    if not client:
        return f"Cliente '{client_name}' não encontrado.", 404

    try:
        result = subprocess.run(['sudo', 'wg', 'show', WG_INTERFACE, 'dump'], capture_output=True, text=True, check=True)
        lines = result.stdout.strip().split('\n')[1:]  # pula cabeçalho

        for line in lines:
            parts = line.split('\t')
            public_key = parts[0]
            endpoint = parts[2]
            allowed_ips = parts[3]
            rx = int(parts[5])
            tx = int(parts[6])

            if public_key == client.public_key:
                client_info = {
                    'name': client.name,
                    'ip_real': endpoint if endpoint else "(sem conexão)",
                    'ip_local': allowed_ips.split('/')[0],
                    'rx': round(rx / (1024 * 1024), 2),
                    'tx': round(tx / (1024 * 1024), 2),
                }
                return render_template('conexoes.html', client=client_info)

        return f"Cliente '{client_name}' não está conectado.", 404

    except subprocess.CalledProcessError as e:
        return f"Erro ao obter conexões: {e}", 500


@app.route('/status')
def status_geral():
    try:
        result = subprocess.run(['sudo', 'wg', 'show', WG_INTERFACE, 'dump'], capture_output=True, text=True, check=True)
        peers = result.stdout.strip().split('\n')[1:]
        agora = int(datetime.now().timestamp())

        # Índice public_key -> linha do wg
        dump = {}
        for line in peers:
            parts = line.split('\t')
            if len(parts) >= 7:
                dump[parts[0]] = parts  # por public_key

        status_list = []
        with SessionLocal() as db:
            for c in db.query(Client).all():
                parts = dump.get(c.public_key)
                if parts:
                    endpoint = parts[2]
                    allowed_ips = parts[3]
                    latest_handshake = int(parts[4])
                    rx = int(parts[5])
                    tx = int(parts[6])
                    segundos = agora - latest_handshake
                    status = "Conectado" if segundos <= 180 else "Desconectado"

                    status_list.append({
                        'name': c.name,
                        'ip_real': endpoint if endpoint else "(sem conexão)",
                        'ip_local': allowed_ips.split('/')[0],
                        'ultimo_handshake': f"{segundos} segundos atrás" if latest_handshake != 0 else "sem handshake",
                        'status': status,
                        'rx': round(rx / (1024 * 1024), 2),
                        'tx': round(tx / (1024 * 1024), 2),
                    })
                else:
                    status_list.append({
                        'name': c.name,
                        'ip_real': "(sem conexão)",
                        'ip_local': c.ip_address,
                        'ultimo_handshake': "sem handshake",
                        'status': "Desconectado",
                        'rx': 0,
                        'tx': 0,
                    })

        return render_template('status.html', clients=status_list)

    except subprocess.CalledProcessError as e:
        return f"Erro ao obter status: {e}", 500


# Executa a aplicação Flask localmente
if __name__ == '__main__':
    print("Endpoint detectado:", get_server_endpoint())
    app.run(host='0.0.0.0', port=5000)
