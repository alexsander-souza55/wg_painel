# 🛡️ WG Painel

# WireGuard Painel

Um painel de gerenciamento do WireGuard desenvolvido em **Flask** com banco de dados **SQLite**.  
O sistema permite:

## ✨ Funcionalidades
- ✅ Criar e gerenciar **peers** e **grupos**  
- 🗂️ Organização de grupos e usuários  
- 👥 Cadastro e gerenciamento de clientes 
- 📊 Visualizar conexões ativas em **tempo real** (upload/download, IP real e local)  
- ⚡ Geração automática de configurações (incluindo para **MikroTik**)   
- 💾 Armazenar dados em banco de dados com **SQLAlchemy**  



Este projeto foi desenvolvido como estudo prático em **Python, Flask, banco de dados e redes**, servindo também como portfólio para oportunidades de trabalho remoto.

---

## 🛠️ Tecnologias Utilizadas

- [Python 3](https://www.python.org/) 🐍  
- [Flask](https://flask.palletsprojects.com/) 🌐  
- SQLite (banco de dados local) 💾  
- HTML, CSS e JS (templates) 🎨  

---

## 🚀 Como rodar o projeto

### 1. Clone o repositório

```bash
git clone https://github.com/SEU_USUARIO/wg_painel.git
cd wg_painel

2. Crie e ative o ambiente virtual
    Linux/macOS
        python3 -m venv venv
        source venv/bin/activate

    Windows
        python -m venv venv
        venv\Scripts\activate

### 2. Instale as dependências

```bash
pip install -r requirements.txt### 3. Execute o aplicativo


### Execute a aplicação no ambiente virtualizado 
```bash
source /venv/bin/activate #ambiente virtual
python app.py

Abra em: 👉 http://localhost:5000

⚠️ Observações

Arquivos sensíveis como bancos de dados (.db, .json) e configurações locais estão listados no .gitignore, para manter o repositório seguro.

Para personalizar variáveis (como porta, endpoint ou chaves), utilize o arquivo config.conf.

📌 Próximos Passos

 Criar sistema de autenticação para usuários

 Melhorar relatórios de uso

 Publicar em servidor de produção



Estrutura dos diretorios

wg_painel/
│── app.py              # aplicação principal Flask
│── config.conf         # configurações locais (ignorada no Git)
│── database/           # scripts e modelos do banco
│── templates/          # páginas HTML
│── static/             # arquivos estáticos (CSS, JS, imagens)
│── requirements.txt    # dependências do projeto
│── README.md           # este arquivo



👨‍💻 Autor

Desenvolvido por Alexsander Souza

**[Alexsander Souza](https://github.com/alexsander-souza55)**  
🔗 [LinkedIn](https://www.linkedin.com/in/alexsander-souza55/)



---

👉 Esse modelo já está **pronto para colar** no seu `README.md`.  
Deixa seu projeto com cara de profissional e organizado.

Quer que eu também prepare um **`requirements.txt` básico só com Flask e libs comuns** (pra você já subir junto com o README)?
