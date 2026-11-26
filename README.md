# InfoCaps (protótipo)

Site informativo sobre CAPS e UBS, com cadastro, login e agenda de consultas (Flask + SQLite).

## Como rodar
    pip install -r requirements.txt
    python app.py
Abra http://127.0.0.1:5000 no navegador. O banco (infocaps.db) é criado sozinho na primeira execução
e as unidades são importadas de `unidades.csv` (dados de Botucatu: UBS/USF da lista oficial da Prefeitura e CAPS AD II Renascer; confira e complete com o CNES).

## Arquivos
- app.py: rotas, regras e segurança  - schema.sql: banco de dados  - unidades.csv: unidades importadas
- templates/: páginas HTML  - static/style.css: estilo
