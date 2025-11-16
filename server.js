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
    // cria tabelas essenciais (não destrói nada)
    await client.query(`
      CREATE TABLE IF NOT EXISTS users (
        id SERIAL PRIMARY KEY,
        name TEXT,
        email TEXT UNIQUE,
        password TEXT,
        is_admin BOOLEAN DEFAULT false,
        city_id INTEGER,
        created_at TIMESTAMP DEFAULT now()
      );

      CREATE TABLE IF NOT EXISTS cities (
        id SERIAL PRIMARY KEY,
        name TEXT UNIQUE
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
        carismas_json TEXT,
        city_id INTEGER REFERENCES cities(id),
        created_at TIMESTAMP DEFAULT now()
      );
    `);

    // popula etapas e carismas base
    const etapas = ['Iniciação','Formação','Missão','Consolidação'];
    for (const e of etapas) {
      await client.query(`INSERT INTO etapas (nome) VALUES ($1) ON CONFLICT (nome) DO NOTHING`, [e]);
    }

    const car = ['Encontro','Animação','Acolhida','Evangelização','Liturgia'];
    for (const c of car) {
      await client.query(`INSERT INTO carismas (nome) VALUES ($1) ON CONFLICT (nome) DO NOTHING`, [c]);
    }

    // popula cities com os nomes já existentes em comunidades.nome_cidade
    await client.query(`
      INSERT INTO cities (name)
      SELECT DISTINCT nome_cidade FROM comunidades
      WHERE nome_cidade IS NOT NULL AND nome_cidade <> ''
      ON CONFLICT (name) DO NOTHING
    `);

    // atualiza comunidades.city_id a partir de cities.name (se ainda NULL)
    await client.query(`
      UPDATE comunidades c
      SET city_id = ct.id
      FROM cities ct
      WHERE ct.name = c.nome_cidade AND (c.city_id IS NULL)
    `);

    // cria índices úteis
    await client.query(`CREATE INDEX IF NOT EXISTS idx_comunidades_city ON comunidades(city_id)`);
    await client.query(`CREATE INDEX IF NOT EXISTS idx_users_city ON users(city_id)`);

    console.log('DB inicializado (tabelas e seeds básicos).');
  } catch (err) {
    console.error("Erro init DB:", err);
  } finally {
    client.release();
  }
}

initDb().catch(err => console.error('initDb catch:', err));

// -------------------- HELPERS --------------------
function gerarToken(user) {
  // inclui city_id e is_admin no payload
  return jwt.sign(
    {
      id: user.id,
      email: user.email,
      is_admin: !!user.is_admin,
      city_id: user.city_id || null
    },
    SECRET,
    { expiresIn: '7d' }
  );
}

async function verificarToken(req, res, next) {
  const header = req.headers.authorization;
  if (!header) return res.status(401).json({ error: 'Sem token' });

  const token = header.split(' ')[1];
  try {
    const payload = jwt.verify(token, SECRET);
    // busca dados atualizados do usuário no banco (incluindo city name)
    const r = await pool.query(
      `SELECT u.id, u.email, u.name, u.is_admin, u.city_id, c.name AS city_name
       FROM users u
       LEFT JOIN cities c ON c.id = u.city_id
       WHERE u.id = $1`,
      [payload.id]
    );

    if (r.rowCount === 0) return res.status(401).json({ error: 'Usuário não encontrado' });

    const dbUser = r.rows[0];
    req.user = {
      id: dbUser.id,
      email: dbUser.email,
      name: dbUser.name,
      is_admin: dbUser.is_admin,
      city_id: dbUser.city_id,
      city_name: dbUser.city_name
    };

    next();
  } catch (err) {
    console.error('verificarToken error:', err);
    return res.status(401).json({ error: 'Token inválido' });
  }
}

function adminOnly(req, res, next) {
  if (!req.user || !req.user.is_admin) {
    return res.status(403).json({ error: 'Acesso negado: administrador somente' });
  }
  next();
}

// -------------------- APP --------------------
const app = express();
app.use(cors());
app.use(bodyParser.json());

// -------------------- ENDPOINTS --------------------

// GET cities (lista usada no frontend)
app.get('/api/cities', async (req, res) => {
  try {
    const r = await pool.query('SELECT id, name FROM cities ORDER BY name');
    res.json(r.rows);
  } catch (err) {
    console.error('cities error:', err);
    res.status(500).json({ error: 'Erro ao buscar cidades' });
  }
});

// REGISTER (aceita city_id opcional)
app.post('/api/register', async (req, res) => {
  const { name, email, password, is_admin, city_id } = req.body;

  if (!email || !password)
    return res.status(400).json({ error: 'Email e senha obrigatórios' });

  const hash = await bcrypt.hash(password, 10);

  try {
    const result = await pool.query(
      `INSERT INTO users (name, email, password, is_admin, city_id)
       VALUES ($1,$2,$3,$4,$5)
       RETURNING id, email, is_admin, city_id`,
      [name || '', email, hash, is_admin || false, city_id || null]
    );

    const user = result.rows[0];
    const token = gerarToken(user);

    // obter city_name para retorno
    let cityName = null;
    if (user.city_id) {
      const c = await pool.query('SELECT name FROM cities WHERE id=$1', [user.city_id]);
      if (c.rowCount) cityName = c.rows[0].name;
    }

    res.json({
      token,
      user: { id: user.id, email: user.email, is_admin: user.is_admin, city_id: user.city_id, city_name: cityName }
    });

  } catch (err) {
    console.error('register error:', err);
    return res.status(400).json({ error: 'Email já cadastrado' });
  }
});

// LOGIN
app.post('/api/login', async (req, res) => {
  const { email, password } = req.body;

  try {
    const r = await pool.query('SELECT * FROM users WHERE email=$1', [email]);
    if (r.rowCount === 0) return res.status(400).json({ error: 'Usuário não encontrado' });

    const user = r.rows[0];
    const ok = await bcrypt.compare(password, user.password);

    if (!ok) return res.status(400).json({ error: 'Senha incorreta' });

    const cityRes = user.city_id ? await pool.query('SELECT id, name FROM cities WHERE id=$1', [user.city_id]) : null;
    const city = cityRes && cityRes.rowCount ? cityRes.rows[0] : null;

    const token = gerarToken({ id: user.id, email: user.email, is_admin: user.is_admin, city_id: user.city_id });

    res.json({
      token,
      user: {
        id: user.id,
        email: user.email,
        name: user.name,
        is_admin: user.is_admin,
        city_id: user.city_id,
        city_name: city ? city.name : null
      }
    });
  } catch (err) {
    console.error('login error:', err);
    res.status(500).json({ error: 'Erro no login' });
  }
});

// UPDATE USER
app.put('/api/user', verificarToken, async (req, res) => {
  const { name, email, password, city_id } = req.body;
  const id = req.user.id;

  const r = await pool.query(`SELECT * FROM users WHERE id=$1`, [id]);
  if (r.rowCount === 0) return res.status(404).json({ error: 'Usuário não encontrado' });

  let hash = r.rows[0].password;
  if (password) hash = await bcrypt.hash(password, 10);

  try {
    await pool.query(`
      UPDATE users SET name=$1, email=$2, password=$3, city_id=$4 WHERE id=$5
    `, [name || r.rows[0].name, email || r.rows[0].email, hash, city_id || r.rows[0].city_id, id]);

    res.json({ ok: true });
  } catch (err) {
    console.error('update user error:', err);
    res.status(400).json({ error: 'Erro ao atualizar (email já usado?)' });
  }
});

// FETCH options (etapas + carismas)
app.get('/api/options', verificarToken, async (req, res) => {
  try {
    const etapas = await pool.query('SELECT * FROM etapas ORDER BY id');
    const carismas = await pool.query('SELECT * FROM carismas ORDER BY id');
    res.json({ etapas: etapas.rows, carismas: carismas.rows });
  } catch (err) {
    console.error('options error:', err);
    res.status(500).json({ error: 'Erro ao buscar options' });
  }
});

// -------------------- CRUD COMUNIDADES --------------------

// LISTAR TODAS (admin vê todas; usuário só vê sua city)
app.get('/api/comunidades', verificarToken, async (req, res) => {
  try {
    if (req.user.is_admin) {
      const r = await pool.query(`
        SELECT c.*, e.nome AS etapa_nome, ct.name AS city_name
        FROM comunidades c
        LEFT JOIN etapas e ON e.id = c.etapa_id
        LEFT JOIN cities ct ON ct.id = c.city_id
        ORDER BY c.id DESC
      `);
      return res.json(r.rows);
    } else {
      const r = await pool.query(`
        SELECT c.*, e.nome AS etapa_nome, ct.name AS city_name
        FROM comunidades c
        LEFT JOIN etapas e ON e.id = c.etapa_id
        LEFT JOIN cities ct ON ct.id = c.city_id
        WHERE c.city_id = $1
        ORDER BY c.id DESC
      `, [req.user.city_id]);
      return res.json(r.rows);
    }
  } catch (err) {
    console.error('comunidades list error:', err);
    res.status(500).json({ error: 'Erro ao listar comunidades' });
  }
});

// LISTAR UMA
app.get('/api/comunidades/:id', verificarToken, async (req, res) => {
  const { id } = req.params;
  const r = await pool.query(`SELECT * FROM comunidades WHERE id=$1`, [id]);
  if (r.rowCount === 0) return res.status(404).json({ error: 'Comunidade não encontrada' });

  // se não admin, só permite ver se pertence à mesma city
  if (!req.user.is_admin && r.rows[0].city_id !== req.user.city_id) {
    return res.status(403).json({ error: 'Acesso negado a essa comunidade' });
  }

  res.json(r.rows[0]);
});

// CRIAR (usuário informa city_id; se não informar, usa user.city_id; admin pode criar em qualquer cidade)
app.post('/api/comunidades', verificarToken, async (req, res) => {
  const data = req.body;
  try {
    const cityId = data.city_id || req.user.city_id || null;

    const r = await pool.query(`
      INSERT INTO comunidades
      (numero_comunidade, nome_diocese, nome_bispo, nome_cidade, nome_paroquia, nome_paroco, nome_vigario, qtd_total, qtd_jovens, etapa_id, data_formacao, data_ultima_etapa, levantados_json, carismas_json, city_id)
      VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14,$15)
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
      cityId
    ]);

    res.json(r.rows[0]);
  } catch (err) {
    console.error('create comunidade error:', err);
    res.status(400).json({ error: 'Erro ao criar comunidade' });
  }
});

// EDITAR
app.put('/api/comunidades/:id', verificarToken, async (req, res) => {
  const { id } = req.params;
  const data = req.body;

  try {
    // busca comunidade
    const orig = await pool.query('SELECT * FROM comunidades WHERE id=$1', [id]);
    if (orig.rowCount === 0) return res.status(404).json({ error: 'Comunidade não encontrada' });

    const origRow = orig.rows[0];

    // se não admin, só permite editar se mesma city
    if (!req.user.is_admin && origRow.city_id !== req.user.city_id) {
      return res.status(403).json({ error: 'Acesso negado para editar essa comunidade' });
    }

    const cityId = (data.city_id !== undefined) ? data.city_id : origRow.city_id;

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
        carismas_json=$14,
        city_id=$15
      WHERE id=$16
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
      cityId,
      id
    ]);

    res.json(r.rows[0]);
  } catch (err) {
    console.error('update comunidade error:', err);
    res.status(400).json({ error: 'Erro ao atualizar comunidade' });
  }
});

// DELETAR
app.delete('/api/comunidades/:id', verificarToken, async (req, res) => {
  const { id } = req.params;

  try {
    const orig = await pool.query('SELECT * FROM comunidades WHERE id=$1', [id]);
    if (orig.rowCount === 0) return res.json({ ok: true });

    if (!req.user.is_admin && orig.rows[0].city_id !== req.user.city_id) {
      return res.status(403).json({ error: 'Acesso negado para deletar essa comunidade' });
    }

    await pool.query(`DELETE FROM comunidades WHERE id=$1`, [id]);
    res.json({ ok: true });
  } catch (err) {
    console.error('delete comunidade error:', err);
    res.status(500).json({ error: 'Erro ao deletar' });
  }
});

// -------------------- DASHBOARD (filtrado por cidade) --------------------
app.get('/api/dashboard', verificarToken, async (req, res) => {
  try {
    const { is_admin, city_id } = req.user;

    const whereComunidade = is_admin ? '' : 'WHERE city_id = $1';
    const whereParams = is_admin ? [] : [city_id];

    // total comunidades
    const totComunidadesQuery = `SELECT COUNT(*)::int AS total FROM comunidades ${whereComunidade}`;
    const totComunidadesRes = await pool.query(totComunidadesQuery, whereParams);
    const totalComunidades = totComunidadesRes.rows[0].total;

    // total pessoas (soma qtd_total)
    const totPessoasQuery = `SELECT COALESCE(SUM(qtd_total),0)::int AS total_pessoas FROM comunidades ${whereComunidade}`;
    const totPessoasRes = await pool.query(totPessoasQuery, whereParams);
    const totalPessoas = totPessoasRes.rows[0].total_pessoas;

    // carismas total (somatório dos arrays em carismas_json) — assume carismas_json é um array JSON
    const carismasCountQuery = is_admin
      ? `SELECT COALESCE(SUM(json_array_length(COALESCE(carismas_json::json,'[]'))),0)::int AS total_carismas FROM comunidades`
      : `SELECT COALESCE(SUM(json_array_length(COALESCE(carismas_json::json,'[]'))),0)::int AS total_carismas FROM comunidades WHERE city_id = $1`;

    const carismasCountRes = await pool.query(carismasCountQuery, whereParams);
    const totalCarismas = carismasCountRes.rows[0].total_carismas || 0;

    // últimas comunidades
    const ultimasQuery = is_admin
      ? `SELECT id, numero_comunidade, nome_diocese, nome_cidade, qtd_total, created_at FROM comunidades ORDER BY id DESC LIMIT 10`
      : `SELECT id, numero_comunidade, nome_diocese, nome_cidade, qtd_total, created_at FROM comunidades WHERE city_id = $1 ORDER BY id DESC LIMIT 10`;

    const ultimasRes = await pool.query(ultimasQuery, whereParams);

    // atividades -- placeholder (você pode adaptar para tabela real de atividades)
    const atividades = {
      total_eventos: 0,
      total_encontros: 0,
      total_outros: 0
    };

    res.json({
      city_id: city_id || null,
      city_name: req.user.city_name || null,
      total_comunidades: totalComunidades,
      total_pessoas: totalPessoas,
      total_carismas: totalCarismas,
      ultimas: ultimasRes.rows,
      atividades
    });

  } catch (err) {
    console.error('dashboard error:', err);
    res.status(500).json({ error: 'Erro ao buscar dashboard' });
  }
});

// -------------------- EXEMPLO ROTAS ADMIN --------------------

// listar usuários (adminOnly)
app.get('/api/users', verificarToken, adminOnly, async (req, res) => {
  try {
    const r = await pool.query(
      `SELECT u.id, u.name, u.email, u.is_admin, u.city_id, c.name AS city_name, u.created_at
       FROM users u
       LEFT JOIN cities c ON c.id = u.city_id
       ORDER BY u.id DESC`
    );
    res.json(r.rows);
  } catch (err) {
    console.error('users list error:', err);
    res.status(500).json({ error: 'Erro ao listar usuários' });
  }
});

// -------------------- SERVER --------------------
const PORT = process.env.PORT || 4000;
app.listen(PORT, () => console.log("Backend rodando na porta", PORT));
