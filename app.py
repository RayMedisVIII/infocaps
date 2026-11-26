import csv, io, os, re, secrets, sqlite3, time
from datetime import datetime
from functools import wraps
from flask import (Flask, Response, abort, flash, g, redirect, render_template,
                   request, session, url_for)
from werkzeug.security import check_password_hash, generate_password_hash

BASE = os.path.dirname(os.path.abspath(__file__))
DB = os.path.join(BASE, "infocaps.db")
TERMO_VERSAO = "1.0"
TIPOS = ["Acolhimento", "Consulta individual", "Grupo", "Oficina", "Outro"]
STATUS = ["Agendada", "Realizada", "Cancelada", "Não compareceu"]

app = Flask(__name__)
app.config.update(SESSION_COOKIE_HTTPONLY=True, SESSION_COOKIE_SAMESITE="Lax",
                  PERMANENT_SESSION_LIFETIME=1800)  # sessão expira em 30 min
key_file = os.path.join(BASE, ".secret_key")
if not os.path.exists(key_file):
    open(key_file, "w").write(secrets.token_hex(32))
app.secret_key = open(key_file).read()


def db():
    if "db" not in g:
        g.db = sqlite3.connect(DB)
        g.db.row_factory = sqlite3.Row
        g.db.execute("PRAGMA foreign_keys = ON")
    return g.db


@app.teardown_appcontext
def close_db(_):
    if "db" in g:
        g.db.close()


def init_db():
    con = sqlite3.connect(DB)
    con.executescript(open(os.path.join(BASE, "schema.sql"), encoding="utf8").read())
    if con.execute("SELECT COUNT(*) FROM unidade").fetchone()[0] == 0:  # importa o CSV
        with open(os.path.join(BASE, "unidades.csv"), encoding="utf8") as f:
            for r in csv.DictReader(f):
                con.execute("INSERT INTO unidade (nome,tipo,modalidade,bairro,telefone) VALUES (?,?,?,?,?)",
                            (r["nome"], r["tipo"], r["modalidade"], r["bairro"], r["telefone"]))
    con.commit()
    con.close()


# ---------- segurança básica ----------
@app.before_request
def proteger():
    session.permanent = True
    if "csrf" not in session:
        session["csrf"] = secrets.token_hex(16)
    if request.method == "POST" and not secrets.compare_digest(
            request.form.get("csrf", ""), session["csrf"]):
        abort(400)


@app.after_request
def cabecalhos(r):
    r.headers["Content-Security-Policy"] = "default-src 'self'; img-src 'self' data:"
    r.headers["X-Content-Type-Options"] = "nosniff"
    r.headers["X-Frame-Options"] = "DENY"
    r.headers["Referrer-Policy"] = "same-origin"
    return r


app.jinja_env.globals["csrf"] = lambda: session.get("csrf", "")
TENTATIVAS = {}  # ip -> [contagem, início]; limita tentativas de login


def login_required(f):
    @wraps(f)
    def w(*a, **k):
        if "uid" not in session:
            return redirect(url_for("login"))
        return f(*a, **k)
    return w


@app.context_processor
def usuario():
    return {"logado": "uid" in session, "nome_usuario": session.get("nome")}


# ---------- páginas ----------
@app.route("/")
def index():
    q, tipo = request.args.get("q", "").strip(), request.args.get("tipo", "")
    sql, par = "SELECT * FROM unidade WHERE (nome LIKE ? OR bairro LIKE ?)", [f"%{q}%"] * 2
    if tipo in ("CAPS", "UBS"):
        sql += " AND tipo = ?"
        par.append(tipo)
    unidades = db().execute(sql + " ORDER BY tipo, nome", par).fetchall()
    return render_template("index.html", unidades=unidades, q=q, tipo=tipo)


@app.route("/termo")
def termo():
    return render_template("termo.html", versao=TERMO_VERSAO)


@app.route("/cadastro", methods=["GET", "POST"])
def cadastro():
    if request.method == "POST":
        nome = request.form.get("nome", "").strip()
        email = request.form.get("email", "").strip().lower()
        senha = request.form.get("senha", "")
        erro = None
        if not nome or len(nome) > 80:
            erro = "Informe um nome ou apelido (até 80 caracteres)."
        elif not re.fullmatch(r"[^@\s]+@[^@\s]+\.[^@\s]+", email):
            erro = "Informe um e-mail válido."
        elif len(senha) < 8 or not re.search(r"\d", senha) or not re.search(r"[A-Za-z]", senha):
            erro = "A senha deve ter 8 ou mais caracteres, com letras e números."
        elif senha != request.form.get("senha2"):
            erro = "As senhas não são iguais."
        elif not request.form.get("aceite"):
            erro = "É necessário aceitar o termo de uso para criar a conta."
        if not erro:
            try:
                db().execute("INSERT INTO usuario (nome,email,senha_hash,termo_versao,termo_aceito_em) VALUES (?,?,?,?,?)",
                             (nome, email, generate_password_hash(senha), TERMO_VERSAO,
                              datetime.now().isoformat(timespec="seconds")))
                db().commit()
                flash("Conta criada. Entre com seu e-mail e senha.")
                return redirect(url_for("login"))
            except sqlite3.IntegrityError:
                erro = "Não foi possível criar a conta com esses dados."
        flash(erro, "erro")
    return render_template("cadastro.html")


@app.route("/login", methods=["GET", "POST"])
def login():
    if request.method == "POST":
        ip = request.remote_addr
        n, ini = TENTATIVAS.get(ip, [0, time.time()])
        if time.time() - ini > 300:
            n, ini = 0, time.time()
        if n >= 5:
            flash("Muitas tentativas. Aguarde alguns minutos.", "erro")
            return render_template("login.html"), 429
        u = db().execute("SELECT * FROM usuario WHERE email = ?",
                         (request.form.get("email", "").strip().lower(),)).fetchone()
        if u and check_password_hash(u["senha_hash"], request.form.get("senha", "")):
            TENTATIVAS.pop(ip, None)
            session.clear()
            session.update(uid=u["id"], nome=u["nome"], csrf=secrets.token_hex(16))
            return redirect(url_for("agenda"))
        TENTATIVAS[ip] = [n + 1, ini]
        flash("E-mail ou senha incorretos.", "erro")
    return render_template("login.html")


@app.route("/sair", methods=["POST"])
def sair():
    session.clear()
    return redirect(url_for("index"))


@app.route("/agenda", methods=["GET", "POST"])
@login_required
def agenda():
    if request.method == "POST":
        try:
            dt = datetime.strptime(request.form["data_hora"], "%Y-%m-%dT%H:%M")
            ok = (request.form["tipo"] in TIPOS and db().execute(
                "SELECT 1 FROM unidade WHERE id = ?", (request.form["unidade"],)).fetchone())
        except (KeyError, ValueError):
            ok = False
        if ok:
            db().execute("INSERT INTO consulta (usuario_id,unidade_id,data_hora,tipo_atendimento) VALUES (?,?,?,?)",
                         (session["uid"], request.form["unidade"], dt.isoformat(timespec="minutes"), request.form["tipo"]))
            db().commit()
        else:
            flash("Preencha data, unidade e tipo de atendimento.", "erro")
        return redirect(url_for("agenda"))
    consultas = db().execute(
        "SELECT c.*, u.nome AS unidade FROM consulta c JOIN unidade u ON u.id = c.unidade_id "
        "WHERE c.usuario_id = ? ORDER BY c.data_hora", (session["uid"],)).fetchall()
    unidades = db().execute("SELECT id, nome FROM unidade ORDER BY tipo, nome").fetchall()
    return render_template("agenda.html", consultas=consultas, unidades=unidades, tipos=TIPOS, status=STATUS)


def minha_consulta(cid):  # cada usuário só acessa as próprias consultas
    c = db().execute("SELECT id FROM consulta WHERE id = ? AND usuario_id = ?", (cid, session["uid"])).fetchone()
    return c or abort(404)


@app.post("/agenda/<int:cid>/status")
@login_required
def mudar_status(cid):
    minha_consulta(cid)
    if request.form.get("status") in STATUS:
        db().execute("UPDATE consulta SET status = ? WHERE id = ?", (request.form["status"], cid))
        db().commit()
    return redirect(url_for("agenda"))


@app.post("/agenda/<int:cid>/excluir")
@login_required
def excluir(cid):
    minha_consulta(cid)
    db().execute("DELETE FROM consulta WHERE id = ?", (cid,))
    db().commit()
    return redirect(url_for("agenda"))


@app.post("/conta/excluir")
@login_required
def excluir_conta():  # direito de exclusão (LGPD): apaga usuário e consultas
    db().execute("DELETE FROM usuario WHERE id = ?", (session["uid"],))
    db().commit()
    session.clear()
    flash("Sua conta e suas consultas foram apagadas.")
    return redirect(url_for("index"))


@app.route("/agenda/relatorio.csv")
@login_required
def relatorio():
    rows = db().execute(
        "SELECT c.data_hora, u.nome, c.tipo_atendimento, c.status FROM consulta c "
        "JOIN unidade u ON u.id = c.unidade_id WHERE c.usuario_id = ? ORDER BY c.data_hora",
        (session["uid"],)).fetchall()
    out = io.StringIO()
    w = csv.writer(out, delimiter=";")
    w.writerow(["Data", "Hora", "Unidade", "Tipo de atendimento", "Situação"])
    for r in rows:
        d, h = r["data_hora"].split("T")
        w.writerow([d, h] + [("'" + x if x[:1] in "=+-@" else x) for x in (r["nome"], r["tipo_atendimento"], r["status"])])
    return Response("﻿" + out.getvalue(), mimetype="text/csv",
                    headers={"Content-Disposition": "attachment; filename=agenda_infocaps.csv"})


init_db()
if __name__ == "__main__":
    app.run(debug=False)
