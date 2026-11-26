CREATE TABLE IF NOT EXISTS usuario (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  nome TEXT NOT NULL,
  email TEXT NOT NULL UNIQUE,
  senha_hash TEXT NOT NULL,
  termo_versao TEXT NOT NULL,
  termo_aceito_em TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS unidade (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  nome TEXT NOT NULL,
  tipo TEXT NOT NULL CHECK (tipo IN ('CAPS','UBS')),
  modalidade TEXT,
  bairro TEXT,
  telefone TEXT
);
CREATE TABLE IF NOT EXISTS consulta (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  usuario_id INTEGER NOT NULL REFERENCES usuario(id) ON DELETE CASCADE,
  unidade_id INTEGER NOT NULL REFERENCES unidade(id),
  data_hora TEXT NOT NULL,
  tipo_atendimento TEXT NOT NULL,
  status TEXT NOT NULL DEFAULT 'Agendada'
    CHECK (status IN ('Agendada','Realizada','Cancelada','Não compareceu'))
);
