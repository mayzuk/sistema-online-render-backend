require('dotenv').config();
const express = require('express');
const bodyParser = require('body-parser');
const cors = require('cors');
const bcrypt = require('bcrypt');
const jwt = require('jsonwebtoken');
const { Pool } = require('pg');

const SECRET = process.env.JWT_SECRET || 'c8f3d7b2c0a948cfa2e4eab7f1e6a92e1d4f3c7a99b24e8f5c1e76a3d2f9b8c1';

const pool = new Pool({
  connectionString: process.env.DATABASE_URL,
  ssl: process.env.DB_SSL === 'true' ? { rejectUnauthorized: false } : false
});

// -------------------- INIT DB --------------------
async function initDb() {
  const client = await pool.connect();
  try {
    await client.query(`
      CREATE TABLE IF NOT EXISTS users (
        id SERIAL PRIMARY KEY,
        name TEXT,
        email TEXT UNIQUE,
        password TEXT,
        is_admin BOOLEAN DEFAULT false,
        created_at TIMESTAMP DEFAULT now()
      );

      CREATE TABLE IF NOT EXISTS etapas (
        id SERIAL PRIMARY KEY,
        nome TEXT UNIQUE
      );

      CREATE TABLE IF NOT EXISTS carismas (
        id SERIAL PRIMARY KEY,
        nome TEXT UNIQUE
      );

      CREATE TABLE IF NOT EXISTS comunidades (
        id SERIAL PRIMARY KEY,
        numero_comunidade TEXT,
        nome_diocese TEXT,
        nome_bispo TEXT,
        nome_cidade TEXT,
        nome_paroquia TEXT,
        nome_paroco TEXT,
        nome_vigario TEXT,
        qtd_total INTEGER,
        qtd_jovens INTEGER,
        etapa_id INTEGER REFERENCES etapas(id),
        data_formacao DATE,
        data_ultima_etapa DATE,
        levantados_json TEXT,
        carismas_json TEXT
      );
    `);

    const etapas = ['Iniciação','Formação','Missão','Consolidação'];
    for (const e of etapas) {
      await client.query(
        `INSERT INTO etapas (nome) VALUES ($1) ON CONFLICT DO NOTHING`,
        [e]
      );
    }

    const car = ['Encontro','Animação','Acolhida','Evangelização','Liturgia'];
    for (const c of car) {
      await client.query(
        `INSERT INTO carismas (nome) VALUES ($1) ON CONFLICT DO NOTHING`,
        [c]
      );
    }

  } catch (err) {
    console.error("Erro init DB:", err);
  } finally {
    client.release();
  }
}

initDb();

// -------------------- HELPERS --------------------
function gerarToken(user) {
  return jwt.sign(
    { id: user.id, email: user.email, is_admin: user.is_admin },
    SECRET,
    { expiresIn: '7d' }
  );
}

function verificarToken(req, res, next) {
  const header = req.headers.authorization;
  if (!header) return res.status(401).json({ error: 'Sem token' });

  const token = header.split(' ')[1];
  try {
    req.user = jwt.verify(token, SECRET);
    next();
  } catch {
    return res.status(401).json({ error: 'Token inválido' });
  }
}

// -------------------- APP --------------------
const app = express();
app.use(cors());
app.use(bodyParser.json());

// -------------------- ROTAS --------------------

// REGISTER
app.post('/api/register', async (req, res) => {
  const { name, email, password, is_admin } = req.body;

  if (!email || !password)
    return res.status(400).json({ error: 'Email e senha obrigatórios' });

  const hash = await bcrypt.hash(password, 10);

  try {
    const result = await pool.query(
      `INSERT INTO users (name, email, password, is_admin)
       VALUES ($1,$2,$3,$4)
       RETURNING id, email, is_admin`,
      [name || '', email, hash, is_admin || false]
    );

    const user = result.rows[0];
    const token = gerarToken(user);
    res.json({ token, user });

  } catch (err) {
    return res.status(400).json({ error: 'Email já cadastrado' });
  }
});

// LOGIN
app.post('/api/login', async (req, res) => {
  const { email, password } = req.body;

  const r = await pool.query('SELECT * FROM users WHERE email=$1', [email]);
  if (r.rowCount === 0) return res.status(400).json({ error: 'Usuário não encontrado' });

  const user = r.rows[0];
  const ok = await bcrypt.compare(password, user.password);

  if (!ok) return res.status(400).json({ error: 'Senha incorreta' });

  const token = gerarToken(user);
  res.json({
    token,
    user: { id: user.id, email: user.email, name: user.name, is_admin: user.is_admin }
  });
});

// UPDATE USER
app.put('/api/user', verificarToken, async (req, res) => {
  const { name, email, password } = req.body;
  const id = req.user.id;

  const r = await pool.query(`SELECT * FROM users WHERE id=$1`, [id]);
  if (r.rowCount === 0) return res.status(404).json({ error: 'Usuário não encontrado' });

  let hash = r.rows[0].password;
  if (password) hash = await bcrypt.hash(password, 10);

  try {
    await pool.query(`
      UPDATE users SET name=$1, email=$2, password=$3 WHERE id=$4
    `, [name || r.rows[0].name, email || r.rows[0].email, hash, id]);

    res.json({ ok: true });
  } catch {
    res.status(400).json({ error: 'Erro ao atualizar (email já usado)' });
  }
});

// FETCH options
app.get('/api/options', verificarToken, async (req, res) => {
  const etapas = await pool.query('SELECT * FROM etapas ORDER BY id');
  const carismas = await pool.query('SELECT * FROM carismas ORDER BY id');
  res.json({ etapas: etapas.rows, carismas: carismas.rows });
});


// -------------------- CRUD COMUNIDADES --------------------

// LISTAR TODAS
app.get('/api/comunidades', verificarToken, async (req, res) => {
  const r = await pool.query(`
    SELECT c.*, e.nome AS etapa_nome
    FROM comunidades c
    LEFT JOIN etapas e ON e.id = c.etapa_id
    ORDER BY c.id DESC
  `);
  res.json(r.rows);
});

// LISTAR UMA
app.get('/api/comunidades/:id', verificarToken, async (req, res) => {
  const { id } = req.params;
  const r = await pool.query(`SELECT * FROM comunidades WHERE id=$1`, [id]);
  if (r.rowCount === 0) return res.status(404).json({ error: 'Comunidade não encontrada' });
  res.json(r.rows[0]);
});

// CRIAR
app.post('/api/comunidades', verificarToken, async (req, res) => {
  const data = req.body;

  try {
    const r = await pool.query(`
      INSERT INTO comunidades
      (numero_comunidade, nome_diocese, nome_bispo, nome_cidade, nome_paroquia, nome_paroco, nome_vigario, qtd_total, qtd_jovens, etapa_id, data_formacao, data_ultima_etapa, levantados_json, carismas_json)
      VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14)
      RETURNING *
    `, [
      data.numero_comunidade,
      data.nome_diocese,
      data.nome_bispo,
      data.nome_cidade,
      data.nome_paroquia,
      data.nome_paroco,
      data.nome_vigario,
      data.qtd_total,
      data.qtd_jovens,
      data.etapa_id,
      data.data_formacao,
      data.data_ultima_etapa,
      JSON.stringify(data.levantados || []),
      JSON.stringify(data.carismas || [])
    ]);

    res.json(r.rows[0]);

  } catch (err) {
    console.error(err);
    res.status(400).json({ error: 'Erro ao criar comunidade' });
  }
});

// EDITAR
app.put('/api/comunidades/:id', verificarToken, async (req, res) => {
  const { id } = req.params;
  const data = req.body;

  try {
    const r = await pool.query(`
      UPDATE comunidades SET
        numero_comunidade=$1,
        nome_diocese=$2,
        nome_bispo=$3,
        nome_cidade=$4,
        nome_paroquia=$5,
        nome_paroco=$6,
        nome_vigario=$7,
        qtd_total=$8,
        qtd_jovens=$9,
        etapa_id=$10,
        data_formacao=$11,
        data_ultima_etapa=$12,
        levantados_json=$13,
        carismas_json=$14
      WHERE id=$15
      RETURNING *
    `, [
      data.numero_comunidade,
      data.nome_diocese,
      data.nome_bispo,
      data.nome_cidade,
      data.nome_paroquia,
      data.nome_paroco,
      data.nome_vigario,
      data.qtd_total,
      data.qtd_jovens,
      data.etapa_id,
      data.data_formacao,
      data.data_ultima_etapa,
      JSON.stringify(data.levantados || []),
      JSON.stringify(data.carismas || []),
      id
    ]);

    res.json(r.rows[0]);
  } catch (err) {
    console.error(err);
    res.status(400).json({ error: 'Erro ao atualizar comunidade' });
  }
});

// DELETAR
app.delete('/api/comunidades/:id', verificarToken, async (req, res) => {
  const { id } = req.params;

  await pool.query(`DELETE FROM comunidades WHERE id=$1`, [id]);
  res.json({ ok: true });
});

// -------------------- SERVER --------------------
const PORT = process.env.PORT || 4000;
app.listen(PORT, () => console.log("Backend rodando na porta", PORT));
