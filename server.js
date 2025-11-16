// =============================================
// =============== CONFIGURAÇÃO =================
// =============================================
require("dotenv").config();
const express = require("express");
const bodyParser = require("body-parser");
const cors = require("cors");
const bcrypt = require("bcrypt");
const jwt = require("jsonwebtoken");
const { Pool } = require("pg");

const SECRET =
  process.env.JWT_SECRET ||
  "c8f3d7b2c0a948cfa2e4eab7f1e6a92e1d4f3c7a99b24e8f5c1e76a3d2f9b8c1";

const pool = new Pool({
  connectionString: process.env.DATABASE_URL,
  ssl: process.env.DB_SSL === "true" ? { rejectUnauthorized: false } : false,
});

// =============================================
// ============= INICIALIZAR BANCO =============
// =============================================
async function initDb() {
  const client = await pool.connect();
  try {
    await client.query(`
      CREATE TABLE IF NOT EXISTS cities (
        id SERIAL PRIMARY KEY,
        name TEXT UNIQUE
      );

      CREATE TABLE IF NOT EXISTS users (
        id SERIAL PRIMARY KEY,
        name TEXT,
        email TEXT UNIQUE,
        password TEXT,
        is_admin BOOLEAN DEFAULT false,
        city_id INTEGER REFERENCES cities(id),
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
        city_id INTEGER REFERENCES cities(id),
        data_formacao DATE,
        data_ultima_etapa DATE,
        levantados_json TEXT,
        carismas_json TEXT
      );
    `);

    // Inserir cidades padrão
    const cidades = ["Foz do Iguaçu", "Curitiba", "Cascavel"];
    for (const c of cidades) {
      await client.query(
        `INSERT INTO cities (name) VALUES ($1)
         ON CONFLICT DO NOTHING`,
        [c]
      );
    }

    // Etapas padrão
    const etapas = ["Iniciação", "Formação", "Missão", "Consolidação"];
    for (const e of etapas) {
      await client.query(
        `INSERT INTO etapas (nome) VALUES ($1) ON CONFLICT DO NOTHING`,
        [e]
      );
    }

    // Carismas padrão
    const car = [
      "Encontro",
      "Animação",
      "Acolhida",
      "Evangelização",
      "Liturgia",
    ];
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

// =============================================
// =============== HELPERS ======================
// =============================================
function gerarToken(user) {
  return jwt.sign(
    { id: user.id, email: user.email, is_admin: user.is_admin, city_id: user.city_id },
    SECRET,
    { expiresIn: "7d" }
  );
}

function verificarToken(req, res, next) {
  const header = req.headers.authorization;
  if (!header) return res.status(401).json({ error: "Sem token" });

  const token = header.split(" ")[1];
  try {
    req.user = jwt.verify(token, SECRET);
    next();
  } catch {
    return res.status(401).json({ error: "Token inválido" });
  }
}

function verificarAdmin(req, res, next) {
  if (!req.user.is_admin) {
    return res.status(403).json({ error: "Acesso negado" });
  }
  next();
}

// =============================================
// =============== APP CONFIG ===================
// =============================================
const app = express();
app.use(cors());
app.use(bodyParser.json());

// =============================================
// ================ ROTAS AUTH ==================
// =============================================

// REGISTER
app.post("/api/register", async (req, res) => {
  const { name, email, password, is_admin, city_id } = req.body;

  if (!email || !password)
    return res.status(400).json({ error: "Email e senha obrigatórios" });

  const hash = await bcrypt.hash(password, 10);

  try {
    const result = await pool.query(
      `INSERT INTO users (name, email, password, is_admin, city_id)
       VALUES ($1,$2,$3,$4,$5)
       RETURNING id, email, is_admin, city_id`,
      [name || "", email, hash, is_admin || false, city_id || null]
    );

    const user = result.rows[0];
    const token = gerarToken(user);
    res.json({ token, user });
  } catch (err) {
    return res.status(400).json({ error: "Email já cadastrado" });
  }
});

// LOGIN
app.post("/api/login", async (req, res) => {
  const { email, password } = req.body;

  const r = await pool.query(`SELECT * FROM users WHERE email=$1`, [email]);
  if (r.rowCount === 0)
    return res.status(400).json({ error: "Usuário não encontrado" });

  const user = r.rows[0];
  const ok = await bcrypt.compare(password, user.password);

  if (!ok) return res.status(400).json({ error: "Senha incorreta" });

  const token = gerarToken(user);
  res.json({
    token,
    user: {
      id: user.id,
      email: user.email,
      name: user.name,
      is_admin: user.is_admin,
      city_id: user.city_id,
    },
  });
});

// =============================================
// ========= ROTAS ADMINISTRATIVAS ==============
// =============================================

// ---- LISTAR TODOS OS USUÁRIOS ----
app.get("/api/admin/users", verificarToken, verificarAdmin, async (req, res) => {
  const r = await pool.query(`
    SELECT u.*, c.name AS city_name
    FROM users u
    LEFT JOIN cities c ON c.id = u.city_id
    ORDER BY u.id DESC
  `);
  res.json(r.rows);
});

// ---- ATUALIZAR USUÁRIO ----
app.put("/api/admin/users/:id", verificarToken, verificarAdmin, async (req, res) => {
  const { id } = req.params;
  const { name, email, is_admin, city_id } = req.body;

  try {
    await pool.query(
      `UPDATE users SET name=$1, email=$2, is_admin=$3, city_id=$4 WHERE id=$5`,
      [name, email, is_admin, city_id, id]
    );
    res.json({ ok: true });
  } catch (err) {
    res.status(400).json({ error: "Erro ao atualizar usuário" });
  }
});

// ---- LISTAR CIDADES ----
app.get("/api/admin/cities", verificarToken, verificarAdmin, async (req, res) => {
  const r = await pool.query(`SELECT * FROM cities ORDER BY name`);
  res.json(r.rows);
});

// ---- CRIAR CIDADE ----
app.post("/api/admin/cities", verificarToken, verificarAdmin, async (req, res) => {
  const { name } = req.body;
  try {
    const r = await pool.query(
      `INSERT INTO cities (name) VALUES ($1) RETURNING *`,
      [name]
    );
    res.json(r.rows[0]);
  } catch {
    res.status(400).json({ error: "Erro ao criar cidade" });
  }
});

// ---- CRUD ETAPAS ----
app.get("/api/admin/etapas", verificarToken, verificarAdmin, async (req, res) => {
  const r = await pool.query(`SELECT * FROM etapas ORDER BY id`);
  res.json(r.rows);
});

// ---- CRUD CARISMAS ----
app.get("/api/admin/carismas", verificarToken, verificarAdmin, async (req, res) => {
  const r = await pool.query(`SELECT * FROM carismas ORDER BY id`);
  res.json(r.rows);
});

// ---- DASHBOARD GLOBAL ----
app.get("/api/admin/dashboard", verificarToken, verificarAdmin, async (req, res) => {
  const totalUsers = (await pool.query(`SELECT COUNT(*) FROM users`)).rows[0].count;
  const totalComunidades = (await pool.query(`SELECT COUNT(*) FROM comunidades`)).rows[0].count;
  const totalCities = (await pool.query(`SELECT COUNT(*) FROM cities`)).rows[0].count;

  res.json({
    totalUsers,
    totalComunidades,
    totalCities
  });
});

// =============================================
// ======== ROTAS DE COMUNIDADES =================
// =============================================

// LISTAR COM FILTRO POR CIDADE
app.get("/api/comunidades", verificarToken, async (req, res) => {
  const city = req.user.city_id;

  const r = await pool.query(
    `
      SELECT c.*, e.nome AS etapa_nome
      FROM comunidades c
      LEFT JOIN etapas e ON e.id = c.etapa_id
      WHERE c.city_id = $1
      ORDER BY c.id DESC
    `,
    [city]
  );

  res.json(r.rows);
});

// CRIAR
app.post("/api/comunidades", verificarToken, async (req, res) => {
  const data = req.body;

  try {
    const r = await pool.query(
      `
      INSERT INTO comunidades
      (numero_comunidade, nome_diocese, nome_bispo, nome_cidade, nome_paroquia, nome_paroco, nome_vigario, qtd_total, qtd_jovens, etapa_id, city_id, data_formacao, data_ultima_etapa, levantados_json, carismas_json)
      VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14,$15)
      RETURNING *
    `,
      [
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
        req.user.city_id,
        data.data_formacao,
        data.data_ultima_etapa,
        JSON.stringify(data.levantados || []),
        JSON.stringify(data.carismas || []),
      ]
    );

    res.json(r.rows[0]);
  } catch (err) {
    console.error(err);
    res.status(400).json({ error: "Erro ao criar comunidade" });
  }
});

// =============================================
// ================ INICIAR SERVIDOR ============
// =============================================
const PORT = process.env.PORT || 4000;
app.listen(PORT, () => console.log("Backend rodando na porta", PORT));
