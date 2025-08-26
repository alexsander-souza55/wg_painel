#arquivo de modelos (tabelas) database/models.py 
from sqlalchemy import Integer, String, ForeignKey
from sqlalchemy.orm import Mapped, mapped_column, relationship
from database import Base

class Group(Base): # tabela de grupos 
    __tablename__ = "groups"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, index=True)
    name: Mapped[str] = mapped_column(String(150), unique=True, nullable=False)

    # dica: tipar o relacionamento ajuda o Pylance
    clients: Mapped[list["Client"]] = relationship("Client", back_populates="group")

class User(Base): # tabela de usuários 
    __tablename__ = "users"

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    username: Mapped[str] = mapped_column(String(150), unique=True, index=True, nullable=False)
    password: Mapped[str] = mapped_column(String(255), nullable=False)

class Client(Base): # tabela de clientes VPN 
    __tablename__ = "clients"

# dica: o nome da tabela no banco de dados é o nome da classe em minúsculo e no plural
    #atibutos do cliente
    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    name: Mapped[str] = mapped_column(String(150), unique=True, index=True, nullable=False)
    ip_address: Mapped[str | None] = mapped_column(String, unique=True)
    private_key: Mapped[str | None] = mapped_column(String)
    public_key: Mapped[str | None] = mapped_column(String)
    server_public_key: Mapped[str | None] = mapped_column(String)
    group_id: Mapped[int | None] = mapped_column(ForeignKey("groups.id"))


    # dica: tipar o relacionamento ajuda o Pylance
    group: Mapped["Group"] = relationship("Group", back_populates="clients")
