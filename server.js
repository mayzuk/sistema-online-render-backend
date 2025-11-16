// =============================================
// =============== CONFIGURAÇÃO =================
// =============================================
require("dotenv").config();
const express = require("express");
const bodyParser = require("body-parser");
const cors = require("cors");
const bcrypt = require("bcrypt");
const jwt = require("jsonwebtoken");
const crypto = require("crypto");
const nodemailer = require("nodemailer");
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
      ALTER TABLE users ADD COLUMN IF NOT EXISTS is_verified BOOLEAN DEFAULT false;
      ALTER TABLE users ADD COLUMN IF NOT EXISTS verify_token TEXT;
      ALTER TABLE users ADD COLUMN IF NOT EXISTS reset_token TEXT;
      ALTER TABLE users ADD COLUMN IF NOT EXISTS reset_token_expire TIMESTAMP;

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
        created_at TIMESTAMP DEFAULT now(),
        is_verified BOOLEAN DEFAULT false,
        verify_token TEXT,
        reset_token TEXT,
        reset_token_expire TIMESTAMP
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
  } catch (err) {
    console.error("Erro init DB:", err);
  } finally {
    client.release();
  }
}
initDb();

// =============================================
// =============== EMAIL CONFIG =================
// =============================================
const transporter = nodemailer.createTransport({
  service: "gmail",
  auth: {
    user: process.env.MAIL_USER,
    pass: process.env.MAIL_PASS,
  },
});

async function sendEmail({ to, subject, html }) {
  await transporter.sendMail({ from: process.env.MAIL_USER, to, subject, html });
}

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

// REGISTER + enviar email de confirmação
app.post("/api/auth/register", async (req, res) => {
  const { name, email, password, city_id } = req.body;

  const hash = await bcrypt.hash(password, 10);
  const verifyToken = crypto.randomBytes(32).toString("hex");

  try {
    const result = await pool.query(
      `INSERT INTO users (name, email, password, city_id, verify_token, is_verified)
       VALUES ($1,$2,$3,$4,$5,false)
       RETURNING *`,
      [name, email, hash, city_id, verifyToken]
    );

    const verifyURL = `${process.env.FRONTEND_URL}/confirm?token=${verifyToken}`;

    await sendEmail({
      to: email,
      subject: "Confirme sua conta",
      html: `
        <h2>Confirme seu cadastro</h2>
        <p>Clique no link para confirmar:</p>
        <a href="${verifyURL}">${verifyURL}</a>
      `,
    });

    res.json({ message: "Conta criada! Verifique seu e-mail." });
  } catch (err) {
    return res.status(400).json({ error: "Email já cadastrado" });
  }
});

// CONFIRMAR CADASTRO
app.get("/api/auth/confirm", async (req, res) => {
  const { token } = req.query;

  const r = await pool.query(`SELECT * FROM users WHERE verify_token=$1`, [token]);
  if (r.rowCount === 0) return res.status(400).json({ error: "Token inválido" });

  await pool.query(
    `UPDATE users SET is_verified=true, verify_token=NULL WHERE id=$1`,
    [r.rows[0].id]
  );

  res.json({ message: "Conta confirmada com sucesso!" });
});

// LOGIN
app.post("/api/login", async (req, res) => {
  const { email, password } = req.body;

  const r = await pool.query(`SELECT * FROM users WHERE email=$1`, [email]);
  if (r.rowCount === 0)
    return res.status(400).json({ error: "Usuário não encontrado" });

  const user = r.rows[0];

  if (!user.is_verified)
    return res.status(403).json({ error: "Confirme seu e-mail antes de entrar." });

  const ok = await bcrypt.compare(password, user.password);
  if (!ok) return res.status(400).json({ error: "Senha incorreta" });

  const token = gerarToken(user);
  res.json({ token, user });
});

// ESQUECI MINHA SENHA
app.post("/api/auth/forgot", async (req, res) => {
  const { email } = req.body;

  const r = await pool.query(`SELECT * FROM users WHERE email=$1`, [email]);
  if (r.rowCount === 0)
    return res.json({ message: "Se o email existir, enviaremos um link." });

  const token = crypto.randomBytes(32).toString("hex");

  await pool.query(
    `UPDATE users SET reset_token=$1, reset_token_expire=NOW() + INTERVAL '1 hour' WHERE id=$2`,
    [token, r.rows[0].id]
  );

  const resetURL = `${process.env.FRONTEND_URL}/reset?token=${token}`;

  await sendEmail({
    to: email,
    subject: "Redefinir senha",
    html: `<p>Clique para redefinir:</p><a href="${resetURL}">${resetURL}</a>`,
  });

  res.json({ message: "Se o email existir, enviamos um link de recuperação." });
});

// RESETAR SENHA
app.post("/api/auth/reset", async (req, res) => {
  const { token, password } = req.body;

  const r = await pool.query(
    `SELECT * FROM users WHERE reset_token=$1 AND reset_token_expire > NOW()`,
    [token]
  );

  if (r.rowCount === 0)
    return res.status(400).json({ error: "Token inválido ou expirado" });

  const hash = await bcrypt.hash(password, 10);

  await pool.query(
    `UPDATE users 
     SET password=$1, reset_token=NULL, reset_token_expire=NULL
     WHERE id=$2`,
    [hash, r.rows[0].id]
  );

  res.json({ message: "Senha redefinida com sucesso!" });
});

// =============================================
// =============== (OUTRAS ROTAS) ===============
// =============================================
// (mantive exatamente como estavam)
// todas suas rotas admin, comunidades etc.
// NÃO REPETI AQUI PARA CABER NA RESPOSTA
// Mas posso te enviar tudo de novo completo se quiser.

// =============================================
// ================ INICIAR SERVIDOR ============
// =============================================
const PORT = process.env.PORT || 4000;
app.listen(PORT, () => console.log("Backend rodando na porta", PORT));
