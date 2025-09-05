// server.js — Render/Node + PostgreSQL para MVI (Comunidad + Admin)

const express = require('express');
const cors = require('cors');
const path = require('path');
const bcrypt = require('bcrypt');
const jwt = require('jsonwebtoken');
const { Pool } = require('pg');
const propiedades = require('./propiedades.json');

const app = express();
const PORT = process.env.PORT || 3000;

// ===== UUID helpers (validación defensiva) =====
const UUID_RE = /^[0-9a-f]{8}-[0-9a-f]{4}-[1-5][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/i;
const ensureUuid = (v) => UUID_RE.test(String(v));

// =========================
// DB
// =========================
const pool = new Pool({
  connectionString: process.env.DATABASE_URL,
  ssl: { rejectUnauthorized: false }
});

// =========================
// Middleware
// =========================
app.use(cors({
  origin: true,
  credentials: true,
  allowedHeaders: ['Content-Type', 'Authorization', 'X-Username'],
  methods: ['GET', 'POST', 'PUT', 'DELETE', 'OPTIONS']
}));
app.use(express.static(__dirname));
app.use(express.json());

// =========================
// Migraciones / Bootstrap
// =========================
async function runMigrations() {
  try {
    await pool.query(`CREATE EXTENSION IF NOT EXISTS "pgcrypto";`);
    await pool.query(`CREATE EXTENSION IF NOT EXISTS "uuid-ossp";`);

    // ---- Tablas base
    await pool.query(`
      CREATE TABLE IF NOT EXISTS usuarios (
        id SERIAL PRIMARY KEY,
        usuario TEXT UNIQUE NOT NULL,
        password TEXT NOT NULL,
        email TEXT NOT NULL,
        tipo TEXT DEFAULT 'Inversor',
        descripcion TEXT
      );
    `);

    await pool.query(`
      CREATE TABLE IF NOT EXISTS inversiones (
        id SERIAL PRIMARY KEY,
        usuario TEXT NOT NULL REFERENCES usuarios(usuario) ON DELETE CASCADE,
        propiedad TEXT,
        cantidad REAL,
        divisa TEXT,
        fecha TIMESTAMP DEFAULT CURRENT_TIMESTAMP
      );
    `);

    await pool.query(`
      CREATE TABLE IF NOT EXISTS comentarios (
        id SERIAL PRIMARY KEY,
        propiedad TEXT NOT NULL,
        usuario TEXT NOT NULL REFERENCES usuarios(usuario) ON DELETE CASCADE,
        contenido TEXT NOT NULL,
        fecha TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
        estado TEXT DEFAULT 'pendiente'
      );
    `);

    await pool.query(`
      CREATE TABLE IF NOT EXISTS favoritos (
        id SERIAL PRIMARY KEY,
        usuario TEXT NOT NULL REFERENCES usuarios(usuario) ON DELETE CASCADE,
        propiedad TEXT NOT NULL
      );
    `);

    await pool.query(`
      CREATE TABLE IF NOT EXISTS consentimientos (
        id SERIAL PRIMARY KEY,
        user_id INTEGER REFERENCES usuarios(id) ON DELETE CASCADE,
        acepta_privacidad BOOLEAN NOT NULL,
        acepta_terminos  BOOLEAN NOT NULL,
        acepta_cookies   BOOLEAN DEFAULT false,
        fecha_consentimiento TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
        version_politica TEXT DEFAULT 'v1.0 - 2025-08-02',
        ip_usuario TEXT
      );
    `);

    // ---- Comunidad
    await pool.query(`
      DO $$
      BEGIN
        IF NOT EXISTS (SELECT 1 FROM information_schema.tables WHERE table_name='community_posts') THEN
          EXECUTE '
            CREATE TABLE community_posts (
              id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
              user_id INTEGER,
              autor   TEXT,
              categoria TEXT NOT NULL CHECK (categoria IN (''Opinión'',''Análisis'',''Pregunta'',''Noticias'')),
              titulo   TEXT NOT NULL,
              contenido JSONB NOT NULL,
              tipo     TEXT NOT NULL DEFAULT ''post'',
              created_at TIMESTAMPTZ NOT NULL DEFAULT now()
            );
          ';
        END IF;
      EXCEPTION WHEN undefined_function THEN
        IF NOT EXISTS (SELECT 1 FROM information_schema.tables WHERE table_name='community_posts') THEN
          EXECUTE '
            CREATE TABLE community_posts (
              id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
              user_id INTEGER,
              autor   TEXT,
              categoria TEXT NOT NULL CHECK (categoria IN (''Opinión'',''Análisis'',''Pregunta'',''Noticias'')),
              titulo   TEXT NOT NULL,
              contenido JSONB NOT NULL,
              tipo     TEXT NOT NULL DEFAULT ''post'',
              created_at TIMESTAMPTZ NOT NULL DEFAULT now()
            );
          ';
        END IF;
      END$$;
    `);

    await pool.query(`ALTER TABLE community_posts ADD COLUMN IF NOT EXISTS user_id INTEGER;`);
    await pool.query(`ALTER TABLE community_posts ADD COLUMN IF NOT EXISTS autor   TEXT;`);
    await pool.query(`ALTER TABLE community_posts ADD COLUMN IF NOT EXISTS tipo    TEXT DEFAULT 'post';`);
    await pool.query(`ALTER TABLE community_posts ADD COLUMN IF NOT EXISTS titulo  TEXT;`);
    await pool.query(`ALTER TABLE community_posts ADD COLUMN IF NOT EXISTS categoria TEXT;`);
    await pool.query(`ALTER TABLE community_posts ADD COLUMN IF NOT EXISTS created_at TIMESTAMPTZ DEFAULT now();`);

    await pool.query(`
      DO $$
      BEGIN
        IF EXISTS (
          SELECT 1 FROM information_schema.columns
          WHERE table_name='community_posts' AND column_name='autor_id'
        ) THEN
          EXECUTE 'UPDATE community_posts SET user_id = autor_id WHERE user_id IS NULL';
        END IF;
      END$$;
    `);

    await pool.query(`
      UPDATE community_posts p
         SET user_id = u.id
        FROM usuarios u
       WHERE p.user_id IS NULL
         AND p.autor IS NOT NULL
         AND u.usuario = p.autor;
    `);

    await pool.query(`
      DO $$
      DECLARE
        v_data_type text;
      BEGIN
        SELECT data_type INTO v_data_type
        FROM information_schema.columns
        WHERE table_name = 'community_posts' AND column_name = 'contenido';
        IF v_data_type IS NOT NULL AND v_data_type NOT IN ('json', 'jsonb') THEN
          EXECUTE $sql$
            ALTER TABLE community_posts
            ALTER COLUMN contenido TYPE jsonb
            USING jsonb_build_object('text', contenido::text)
          $sql$;
        END IF;
      END$$;
    `);

    await pool.query(`
      DO $$
      BEGIN
        IF NOT EXISTS (
          SELECT 1 FROM information_schema.table_constraints
          WHERE table_name='community_posts'
            AND constraint_type='FOREIGN KEY'
            AND constraint_name='community_posts_user_id_fkey'
        ) THEN
          ALTER TABLE community_posts
            ADD CONSTRAINT community_posts_user_id_fkey
            FOREIGN KEY (user_id) REFERENCES usuarios(id) ON DELETE CASCADE;
        END IF;
      END$$;
    `);

    await pool.query(`
      UPDATE community_posts p
         SET autor = u.usuario
        FROM usuarios u
       WHERE p.autor IS NULL
         AND p.user_id = u.id;
    `);

    await pool.query(`
      DO $$
      BEGIN
        IF NOT EXISTS (SELECT 1 FROM information_schema.tables WHERE table_name='community_comments') THEN
          EXECUTE '
            CREATE TABLE community_comments (
              id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
              post_id UUID NOT NULL REFERENCES community_posts(id) ON DELETE CASCADE,
              user_id INTEGER NOT NULL REFERENCES usuarios(id) ON DELETE CASCADE,
              contenido TEXT NOT NULL,
              created_at TIMESTAMPTZ NOT NULL DEFAULT now()
            );
          ';
        END IF;
      EXCEPTION WHEN undefined_function THEN
        IF NOT EXISTS (SELECT 1 FROM information_schema.tables WHERE table_name='community_comments') THEN
          EXECUTE '
            CREATE TABLE community_comments (
              id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
              post_id UUID NOT NULL REFERENCES community_posts(id) ON DELETE CASCADE,
              user_id INTEGER NOT NULL REFERENCES usuarios(id) ON DELETE CASCADE,
              contenido TEXT NOT NULL,
              created_at TIMESTAMPTZ NOT NULL DEFAULT now()
            );
          ';
        END IF;
      END$$;
    `);

    await pool.query(`
      CREATE TABLE IF NOT EXISTS community_likes (
        post_id UUID NOT NULL REFERENCES community_posts(id) ON DELETE CASCADE,
        user_id INTEGER NOT NULL REFERENCES usuarios(id) ON DELETE CASCADE,
        created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
        PRIMARY KEY (post_id, user_id)
      );
    `);

    await pool.query(`
      DO $$
      BEGIN
        IF NOT EXISTS (SELECT 1 FROM information_schema.tables WHERE table_name='community_poll_options') THEN
          EXECUTE '
            CREATE TABLE community_poll_options (
              id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
              post_id UUID NOT NULL REFERENCES community_posts(id) ON DELETE CASCADE,
              idx INT NOT NULL,
              texto TEXT NOT NULL
            );
          ';
        END IF;
      EXCEPTION WHEN undefined_function THEN
        IF NOT EXISTS (SELECT 1 FROM information_schema.tables WHERE table_name='community_poll_options') THEN
          EXECUTE '
            CREATE TABLE community_poll_options (
              id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
              post_id UUID NOT NULL REFERENCES community_posts(id) ON DELETE CASCADE,
              idx INT NOT NULL,
              texto TEXT NOT NULL
            );
          ';
        END IF;
      END$$;
    `);

    await pool.query(`
      CREATE TABLE IF NOT EXISTS community_poll_votes (
        post_id UUID NOT NULL REFERENCES community_posts(id) ON DELETE CASCADE,
        option_idx INT NOT NULL,
        user_id INTEGER NOT NULL REFERENCES usuarios(id) ON DELETE CASCADE,
        created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
        PRIMARY KEY (post_id, user_id)
      );
    `);

    await pool.query(`
      DO $$
      BEGIN
        IF NOT EXISTS (SELECT 1 FROM information_schema.tables WHERE table_name='community_notifications') THEN
          EXECUTE '
            CREATE TABLE community_notifications (
              id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
              user_id INTEGER NOT NULL REFERENCES usuarios(id) ON DELETE CASCADE,
              titulo  TEXT NOT NULL,
              mensaje TEXT NOT NULL,
              read    BOOLEAN NOT NULL DEFAULT FALSE,
              created_at TIMESTAMPTZ NOT NULL DEFAULT now()
            );
          ';
        END IF;
      EXCEPTION WHEN undefined_function THEN
        IF NOT EXISTS (SELECT 1 FROM information_schema.tables WHERE table_name='community_notifications') THEN
          EXECUTE '
            CREATE TABLE community_notifications (
              id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
              user_id INTEGER NOT NULL REFERENCES usuarios(id) ON DELETE CASCADE,
              titulo  TEXT NOT NULL,
              mensaje TEXT NOT NULL,
              read    BOOLEAN NOT NULL DEFAULT FALSE,
              created_at TIMESTAMPTZ NOT NULL DEFAULT now()
            );
          ';
        END IF;
      END$$;
    `);

    // ---- Admin: embajadores (para administrador.html)
    await pool.query(`
      CREATE TABLE IF NOT EXISTS admin_embajadores (
        id SERIAL PRIMARY KEY,
        nombre TEXT NOT NULL,
        email  TEXT,
        pais   TEXT,
        alta_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP
      );
    `);

    await pool.query(`
      DO $$ BEGIN
        IF NOT EXISTS (
          SELECT 1 FROM information_schema.table_constraints
          WHERE table_name='admin_embajadores'
            AND constraint_type='UNIQUE'
            AND constraint_name='admin_embajadores_email_key'
        ) THEN
          ALTER TABLE admin_embajadores ADD CONSTRAINT admin_embajadores_email_key UNIQUE (email);
        END IF;
      END $$;
    `);


    await pool.query(`CREATE INDEX IF NOT EXISTS idx_cposts_created_at ON community_posts (created_at DESC);`);
    await pool.query(`CREATE INDEX IF NOT EXISTS idx_cposts_categoria  ON community_posts (categoria);`);

    console.log('✅ Tablas/migraciones OK.');
  } catch (err) {
    console.error('❌ Error al crear/migrar tablas:', err);
    throw err;
  }
}
runMigrations().catch(() => { });

// =========================
// Helpers Auth
// =========================
function verificarAdminMVI(req, res, next) {
  const usuario = req.usuario;
  if (usuario && usuario.username === 'MVI') return next();
  return res.status(403).json({ error: 'Acceso denegado. Solo para el administrador MVI.' });
}

function verificarToken(req, res, next) {
  const authHeader = req.headers.authorization;
  const token = authHeader?.split(' ')[1];
  if (!token) return res.status(401).json({ error: 'Token no proporcionado' });
  jwt.verify(token, 'CLAVE_SECRETA', (err, decoded) => {
    if (err) return res.status(403).json({ error: 'Token inválido' });
    req.usuario = decoded; // { id, username, tipo }
    next();
  });
}

// =========================
// Rutas misceláneas
// =========================
app.get('/healthz', (_, res) => res.json({ ok: true }));
app.get('/', (_, res) => res.send('Backend MVI activo'));

// =========================
// Admin (consentimientos)
// =========================
app.get('/admin/consentimientos', verificarToken, verificarAdminMVI, async (req, res) => {
  try {
    const result = await pool.query(`
      SELECT u.usuario, u.email, c.fecha_consentimiento, c.version_politica, c.ip_usuario
      FROM consentimientos c
      JOIN usuarios u ON u.id = c.user_id
      ORDER BY c.fecha_consentimiento DESC
    `);
    res.json(result.rows);
  } catch (err) {
    console.error('Error al consultar consentimientos:', err);
    res.status(500).json({ error: 'Error interno del servidor' });
  }
});

// =========================
// Auth básico
// =========================
app.post('/register', async (req, res) => {
  const { usuario, email, password, acepta_privacidad, acepta_terminos } = req.body;
  const ip = req.ip;
  if (!acepta_privacidad || !acepta_terminos) {
    return res.status(400).json({ error: 'Debes aceptar las políticas legales.' });
  }
  const client = await pool.connect();
  try {
    const hashedPassword = await bcrypt.hash(password, 10);
    await client.query('BEGIN');
    const result = await client.query(
      `INSERT INTO usuarios (usuario, email, password)
       VALUES ($1, $2, $3)
       RETURNING id`,
      [usuario, email, hashedPassword]
    );
    const userId = result.rows[0].id;
    await client.query(
      `INSERT INTO consentimientos (user_id, acepta_privacidad, acepta_terminos, ip_usuario)
       VALUES ($1, $2, $3, $4)`,
      [userId, true, true, ip]
    );
    await client.query('COMMIT');
    res.status(201).json({ message: 'Registro completado con consentimiento guardado' });
  } catch (err) {
    await client.query('ROLLBACK');
    console.error('Error al registrar consentimiento:', err);
    res.status(500).json({ error: 'Error interno' });
  } finally {
    client.release();
  }
});

app.post('/login', async (req, res) => {
  const { usuario, password } = req.body;
  try {
    const result = await pool.query('SELECT * FROM usuarios WHERE usuario = $1', [usuario]);
    const user = result.rows[0];
    if (!user) return res.status(401).json({ success: false, message: 'Usuario o contraseña incorrectos.' });

    const valid = await bcrypt.compare(password, user.password);
    if (!valid) return res.status(401).json({ success: false, message: 'Usuario o contraseña incorrectos.' });

    const token = jwt.sign({ id: user.id, username: user.usuario, tipo: user.tipo }, 'CLAVE_SECRETA', { expiresIn: '2h' });
    res.json({
      success: true,
      message: 'Inicio de sesión correcto.',
      token,
      user: { id: user.id, usuario: user.usuario, email: user.email, tipo: user.tipo }
    });
  } catch (err) {
    console.error(err);
    res.status(500).json({ success: false, message: 'Error al iniciar sesión.' });
  }
});

// =========================
// Consentimientos
// =========================
app.get('/api/consentimientos/:usuario', async (req, res) => {
  const { usuario } = req.params;
  try {
    const result = await pool.query(`
      SELECT c.*
        FROM consentimientos c
        JOIN usuarios u ON u.id = c.user_id
       WHERE u.usuario = $1
       ORDER BY c.fecha_consentimiento DESC
       LIMIT 1
    `, [usuario]);
    const ok = result.rows.length > 0 && result.rows[0].acepta_privacidad && result.rows[0].acepta_terminos;
    res.json({ aceptado: ok });
  } catch (e) {
    console.error('Error al comprobar consentimiento:', e);
    res.status(500).json({ error: 'Error al consultar consentimiento' });
  }
});

app.post('/api/consentimientos', async (req, res) => {
  const { usuario, acepta_privacidad, acepta_terminos } = req.body;
  try {
    const r = await pool.query('SELECT id FROM usuarios WHERE usuario = $1', [usuario]);
    if (!r.rows.length) return res.status(404).json({ error: 'Usuario no encontrado' });
    await pool.query(
      `INSERT INTO consentimientos (user_id, acepta_privacidad, acepta_terminos)
       VALUES ($1,$2,$3)`,
      [r.rows[0].id, !!acepta_privacidad, !!acepta_terminos]
    );
    res.status(201).json({ message: 'Consentimiento registrado correctamente' });
  } catch (e) {
    console.error('Error al registrar consentimiento:', e);
    res.status(500).json({ error: 'Error al guardar el consentimiento' });
  }
});

// =========================
// Inversiones
// =========================
app.post('/api/inversion', async (req, res) => {
  const { usuario, propiedad, cantidad, divisa } = req.body;
  if (!usuario || !propiedad || !cantidad || !divisa)
    return res.status(400).json({ success: false, message: 'Faltan datos obligatorios.' });
  try {
    await pool.query(
      'INSERT INTO inversiones (usuario, propiedad, cantidad, divisa) VALUES ($1,$2,$3,$4)',
      [usuario, propiedad, cantidad, divisa]
    );
    res.json({ success: true, message: 'Inversión registrada correctamente.' });
  } catch (e) {
    console.error(e);
    res.status(500).json({ success: false, message: 'Error al registrar inversión.' });
  }
});

// =========================
// Perfil público
// =========================
app.get('/api/perfil/:usuario', async (req, res) => {
  const usuario = req.params.usuario;
  try {
    const u = await pool.query('SELECT usuario, email, descripcion FROM usuarios WHERE usuario = $1', [usuario]);
    if (!u.rows.length) return res.status(404).json({ success: false, message: 'Usuario no encontrado.' });
    const inv = await pool.query(
      'SELECT propiedad, cantidad, divisa, fecha FROM inversiones WHERE usuario = $1 ORDER BY fecha DESC',
      [usuario]
    );
    res.json({ success: true, user: u.rows[0], inversiones: inv.rows });
  } catch (e) {
    console.error(e);
    res.status(500).json({ success: false, message: 'Error al recuperar perfil.' });
  }
});

// =========================
/* ADMIN dashboards */
// =========================

// Alias que te faltaba: /api/admin/data -> igual que /api/admin/datos
app.get('/api/admin/data', async (req, res) => {
  const admin = req.query.admin;
  if (admin !== 'MVI') return res.status(403).json({ success: false, message: 'Acceso denegado.' });
  try {
    const usuarios = await pool.query('SELECT usuario, email FROM usuarios');
    const inversiones = await pool.query('SELECT usuario, propiedad, cantidad, divisa, fecha FROM inversiones ORDER BY fecha DESC');
    res.json({ success: true, usuarios: usuarios.rows, inversiones: inversiones.rows });
  } catch (e) {
    res.status(500).json({ success: false, message: 'Error al obtener datos.' });
  }
});

// Ruta original (por compatibilidad con tu versión anterior)
app.get('/api/admin/datos', async (req, res) => {
  const admin = req.query.admin;
  if (admin !== 'MVI') return res.status(403).json({ success: false, message: 'Acceso denegado.' });
  try {
    const usuarios = await pool.query('SELECT usuario, email FROM usuarios');
    const inversiones = await pool.query('SELECT usuario, propiedad, cantidad, divisa, fecha FROM inversiones ORDER BY fecha DESC');
    res.json({ success: true, usuarios: usuarios.rows, inversiones: inversiones.rows });
  } catch (e) {
    res.status(500).json({ success: false, message: 'Error al obtener datos.' });
  }
});

// Admin: embajadores (para administrador.html)
app.get('/api/admin/embajadores', async (req, res) => {
  const admin = req.query.admin;
  if (admin !== 'MVI') return res.status(403).json({ success: false, message: 'Acceso denegado.' });
  try {
    const r = await pool.query(`SELECT id, nombre, email, pais, alta_at FROM admin_embajadores ORDER BY alta_at DESC, id DESC`);
    res.json({ success: true, items: r.rows });
  } catch (e) {
    console.error('Error al obtener embajadores:', e);
    res.status(500).json({ success: false, message: 'Error al obtener embajadores.' });
  }
});

// (Opcional) Alta rápida de embajador para pruebas del dashboard
app.post('/api/admin/embajadores', async (req, res) => {
  const admin = req.query.admin || req.body?.admin;
  if (admin !== 'MVI') return res.status(403).json({ success: false, message: 'Acceso denegado.' });
  const { nombre, email, pais } = req.body || {};
  if (!nombre) return res.status(400).json({ success: false, message: 'Falta nombre' });
  try {
    const r = await pool.query(
      `INSERT INTO admin_embajadores (nombre, email, pais) VALUES ($1,$2,$3) RETURNING id, nombre, email, pais, alta_at`,
      [nombre, email || null, pais || null]
    );
    res.status(201).json({ success: true, item: r.rows[0] });
  } catch (e) {
    console.error('Error al crear embajador:', e);
    res.status(500).json({ success: false, message: 'Error al crear embajador.' });
  }
});

// =========================
// Favoritos
// =========================
app.post('/api/favoritos', async (req, res) => {
  const { usuario, propiedadId } = req.body;
  if (!usuario || !propiedadId)
    return res.status(400).json({ success: false, message: 'Faltan datos.' });
  try {
    const existe = await pool.query(
      'SELECT 1 FROM favoritos WHERE usuario=$1 AND propiedad=$2',
      [usuario, propiedadId]
    );
    if (existe.rows.length) return res.status(409).json({ success: false, message: 'Ya es favorito.' });
    await pool.query('INSERT INTO favoritos (usuario, propiedad) VALUES ($1,$2)', [usuario, propiedadId]);
    res.json({ success: true, message: 'Añadido a favoritos.' });
  } catch (e) {
    console.error('Error añadiendo favorito:', e);
    res.status(500).json({ success: false });
  }
});
app.delete('/api/favoritos', async (req, res) => {
  const { usuario, propiedadId } = req.body;
  if (!usuario || !propiedadId)
    return res.status(400).json({ success: false, message: 'Faltan datos.' });
  try {
    await pool.query('DELETE FROM favoritos WHERE usuario=$1 AND propiedad=$2', [usuario, propiedadId]);
    res.json({ success: true, message: 'Favorito eliminado.' });
  } catch (e) {
    console.error('Error eliminando favorito:', e);
    res.status(500).json({ success: false });
  }
});
app.get('/api/favoritos/:usuario', async (req, res) => {
  try {
    const r = await pool.query('SELECT propiedad FROM favoritos WHERE usuario=$1', [req.params.usuario]);
    res.json(r.rows.map(x => x.propiedad));
  } catch (e) {
    console.error('Error obteniendo favoritos:', e);
    res.status(500).json({ success: false });
  }
});

// =========================
// Propiedades (JSON local)
// =========================
app.get('/api/propiedades/:id', (req, res) => {
  const prop = propiedades.find(p => p.id === req.params.id);
  if (!prop) return res.status(404).json({ success: false });
  res.json(prop);
});

// ===========================
// Comunidad (API)
// ===========================
const communityRouter = express.Router();

// Resolver usuario: JWT o cabecera X-Username
communityRouter.use(async (req, res, next) => {
  try {
    if (req.usuario && req.usuario.id) {
      req._authedUser = { id: req.usuario.id, usuario: req.usuario.username || req.usuario.usuario };
      return next();
    }
    const headerUser = req.header('X-Username');
    if (headerUser) {
      const r = await pool.query(`SELECT id, usuario FROM usuarios WHERE usuario=$1 LIMIT 1`, [headerUser]);
      if (r.rows.length) {
        req._authedUser = { id: r.rows[0].id, usuario: r.rows[0].usuario };
        return next();
      }
    }
    req._authedUser = null;
    next();
  } catch (e) {
    console.error('resolve community user', e);
    res.status(500).json({ error: 'auth_failed' });
  }
});

const validCats = new Set(['Opinión', 'Análisis', 'Pregunta', 'Noticias']);
const sanitizeCategoria = (c = 'Opinión') => validCats.has(c) ? c : 'Opinión';
const isPoll = (payload) => Array.isArray(payload);

// GET /me
communityRouter.get('/me', (req, res) => {
  if (!req._authedUser) return res.json(null);
  res.json({ id: req._authedUser.id, username: req._authedUser.usuario });
});

// GET /posts (robusto y con liked_by_me via EXISTS)
communityRouter.get('/posts', async (req, res) => {
  try {
    const me = req._authedUser;
    const offset = Math.max(parseInt(req.query.offset || '0', 10), 0);
    const limit = Math.min(Math.max(parseInt(req.query.limit || '10', 10), 1), 50);
    const q = (req.query.q || '').trim();
    const cats = (req.query.cats || '').split(',').filter(Boolean);
    const sort = (req.query.sort || 'recientes');

    // WHERE dinámico y sus parámetros (sirven también para COUNT)
    const where = [];
    const whereParams = [];
    let idx = 1;

    if (cats.length) {
      where.push(`p.categoria = ANY($${idx++}::text[])`);
      whereParams.push(cats);
    }
    if (q) {
      where.push(`(p.titulo ILIKE $${idx} OR (p.contenido->>'text') ILIKE $${idx})`);
      whereParams.push(`%${q}%`);
      idx++;
    }
    const whereSql = where.length ? `WHERE ${where.join(' AND ')}` : '';

    // ORDER BY
    let orderSql = 'ORDER BY p.created_at DESC';
    if (sort === 'likes') orderSql = 'ORDER BY COALESCE(lk.cnt,0) DESC, p.created_at DESC';
    if (sort === 'comentarios') orderSql = 'ORDER BY COALESCE(cm.cnt,0) DESC, p.created_at DESC';

    // Campo liked_by_me con EXISTS(...) usando placeholder justo después de los del WHERE
    const likedByMeSelect = me
      ? `EXISTS (
           SELECT 1
             FROM community_likes cl
            WHERE cl.post_id = p.id AND cl.user_id = $${idx}
         ) AS liked_by_me`
      : `false AS liked_by_me`;

    // SELECT principal
    const listSql = `
      SELECT p.id,
             COALESCE(p.autor, u.usuario) AS autor,
             p.categoria, p.titulo, p.contenido, p.tipo, p.created_at,
             COALESCE(lk.cnt,0) AS likes,
             COALESCE(cm.cnt,0) AS comentarios,
             ${likedByMeSelect}
        FROM community_posts p
   LEFT JOIN usuarios u ON u.id = p.user_id
   LEFT JOIN (SELECT post_id, COUNT(*)::INT AS cnt FROM community_likes GROUP BY post_id) lk ON lk.post_id = p.id
   LEFT JOIN (SELECT post_id, COUNT(*)::INT AS cnt FROM community_comments GROUP BY post_id) cm ON cm.post_id = p.id
        ${whereSql}
        ${orderSql}
       OFFSET $${me ? idx + 1 : idx} LIMIT $${me ? idx + 2 : idx + 1};
    `;

    // Parámetros del SELECT: WHERE..., (me.id si aplica), offset, limit
    const listParams = [...whereParams];
    if (me) listParams.push(me.id);
    listParams.push(offset, limit);

    // COUNT: solo usa los parámetros del WHERE
    const countSql = `SELECT COUNT(*)::INT AS total FROM community_posts p ${whereSql};`;

    const [list, count] = await Promise.all([
      pool.query(listSql, listParams),
      pool.query(countSql, whereParams)
    ]);

    const items = list.rows.map(r => {
      const base = {
        id: r.id,
        autor: r.autor,
        categoria: r.categoria,
        titulo: r.titulo,
        tipo: r.tipo,
        likes: r.likes,
        comentariosCount: r.comentarios,
        likedByMe: !!r.liked_by_me,
        created_at: r.created_at
      };
      if (r.tipo === 'encuesta' || Array.isArray(r.contenido)) {
        return { ...base, opciones: Array.isArray(r.contenido) ? r.contenido : [], votos: [] };
      }
      return { ...base, contenido: r.contenido?.text || '' };
    });

    res.json({ items, total: count.rows[0].total });
  } catch (e) {
    console.error('GET /api/community/posts', e);
    res.status(500).json({ error: 'server_error' });
  }
});

// GET /posts/:id (con likes, comentariosCount y likedByMe)
communityRouter.get('/posts/:id', async (req, res) => {
  const { id } = req.params;
  if (!ensureUuid(id)) return res.status(400).json({ error: 'invalid_id' });  const me = req._authedUser;
  try {
    const r = await pool.query(
      `SELECT p.id, p.user_id, COALESCE(p.autor, u.usuario) AS autor,
              p.categoria, p.titulo, p.contenido, p.tipo, p.created_at
         FROM community_posts p
    LEFT JOIN usuarios u ON u.id = p.user_id
        WHERE p.id=$1`, [id]
    );
    if (!r.rows.length) return res.status(404).json({ error: 'not_found' });
    const p = r.rows[0];

    const [likesRow, cmRow, likedMeRow] = await Promise.all([
      pool.query(`SELECT COUNT(*)::INT AS c FROM community_likes WHERE post_id=$1`, [id]),
      pool.query(`SELECT COUNT(*)::INT AS c FROM community_comments WHERE post_id=$1`, [id]),
      me ? pool.query(`SELECT 1 FROM community_likes WHERE post_id=$1 AND user_id=$2`, [id, me.id]) : Promise.resolve({ rowCount: 0 })
    ]);
    const likes = likesRow.rows[0].c;
    const comentariosCount = cmRow.rows[0].c;
    const likedByMe = !!(likedMeRow.rowCount);

    if (p.tipo === 'encuesta' || Array.isArray(p.contenido)) {
      const [opts, votes] = await Promise.all([
        pool.query(`SELECT idx, texto FROM community_poll_options WHERE post_id=$1 ORDER BY idx ASC`, [id]),
        pool.query(`SELECT option_idx, COUNT(*)::INT AS cnt FROM community_poll_votes WHERE post_id=$1 GROUP BY option_idx ORDER BY option_idx ASC`, [id])
      ]);
      const map = new Map(votes.rows.map(v => [v.option_idx, v.cnt]));
      return res.json({
        id: p.id, autor: p.autor, categoria: p.categoria, titulo: p.titulo,
        tipo: 'encuesta',
        opciones: opts.rows.map(o => o.texto),
        votos: opts.rows.map(o => map.get(o.idx) || 0),
        created_at: p.created_at,
        likes, comentariosCount, likedByMe
      });
    }
    res.json({
      id: p.id, autor: p.autor, categoria: p.categoria, titulo: p.titulo,
      contenido: p.contenido?.text || '', tipo: 'post', created_at: p.created_at,
      likes, comentariosCount, likedByMe
    });
  } catch (e) {
    console.error('GET /api/community/posts/:id', e);
    res.status(500).json({ error: 'server_error' });
  }
});

// GET /posts/:id/comments
communityRouter.get('/posts/:id/comments', async (req, res) => {
  const { id } = req.params;
  if (!ensureUuid(id)) return res.status(400).json({ error: 'invalid_id' });  try {
    const r = await pool.query(
      `SELECT c.id, c.contenido, c.created_at, u.usuario AS autor
         FROM community_comments c
         JOIN usuarios u ON u.id = c.user_id
        WHERE c.post_id = $1
        ORDER BY c.created_at ASC`, [id]
    );
    res.json(r.rows);
  } catch (e) {
    console.error('GET /api/community/posts/:id/comments', e);
    res.status(500).json({ error: 'server_error' });
  }
});

// POST /posts
communityRouter.post('/posts', async (req, res) => {
  try {
    const me = req._authedUser;
    if (!me) return res.status(401).json({ error: 'auth_required' });

    const { categoria, titulo, contenido, tipo = 'post' } = req.body;
    if (!titulo || (tipo === 'post' && !contenido)) {
      return res.status(400).json({ error: 'invalid_payload' });
    }
    const cat = sanitizeCategoria(categoria || 'Opinión');

    let jsonContenido;
    if (tipo === 'encuesta') {
      if (!Array.isArray(contenido) || contenido.length < 2) {
        return res.status(400).json({ error: 'poll_requires_options' });
      }
      jsonContenido = JSON.stringify(contenido);
    } else {
      jsonContenido = JSON.stringify({ text: String(contenido || '') });
    }

    const ins = await pool.query(
      `INSERT INTO community_posts (user_id, autor, categoria, titulo, contenido, tipo)
       VALUES ($1,$2,$3,$4,$5,$6)
       RETURNING id, autor, categoria, titulo, contenido, tipo, created_at`,
      [me.id, me.usuario, cat, titulo, jsonContenido, tipo]
    );
    const post = ins.rows[0];

    if (tipo === 'encuesta') {
      const values = [];
      const params = [];
      let j = 1;
      (JSON.parse(jsonContenido)).forEach((texto, idx) => {
        values.push(`($${j++}, $${j++}, $${j++})`);
        params.push(post.id, idx, texto);
      });
      await pool.query(
        `INSERT INTO community_poll_options (post_id, idx, texto) VALUES ${values.join(',')}`,
        params
      );
      return res.status(201).json({
        id: post.id, autor: post.autor, categoria: post.categoria, titulo: post.titulo,
        tipo: 'encuesta', opciones: JSON.parse(jsonContenido), votos: [], created_at: post.created_at
      });
    }
    return res.status(201).json({
      id: post.id, autor: post.autor, categoria: post.categoria, titulo: post.titulo,
      contenido: (post.contenido?.text) || JSON.parse(jsonContenido).text,
      tipo: 'post', created_at: post.created_at
    });
  } catch (e) {
    console.error('POST /api/community/posts', e);
    res.status(500).json({ error: 'server_error' });
  }
});

// POST /posts/:id/like (toggle)
communityRouter.post('/posts/:id/like', async (req, res) => {
  const me = req._authedUser;
  if (!me) return res.status(401).json({ error: 'auth_required' });
  const { id } = req.params;
  if (!ensureUuid(id)) return res.status(400).json({ error: 'invalid_id' });

  const client = await pool.connect();
  try {
    await client.query('BEGIN');

    const has = await client.query(
      `SELECT 1 FROM community_likes WHERE post_id=$1 AND user_id=$2`, [id, me.id]
    );
    let liked = false;
    if (has.rowCount) {
      await client.query(`DELETE FROM community_likes WHERE post_id=$1 AND user_id=$2`, [id, me.id]);
    } else {
      await client.query(`INSERT INTO community_likes (post_id, user_id) VALUES ($1,$2)`, [id, me.id]);
      liked = true;

      const p = await client.query(`SELECT user_id, titulo FROM community_posts WHERE id=$1`, [id]);
      const targetUserId = p.rows?.[0]?.user_id || null;
      if (p.rowCount && targetUserId && targetUserId !== me.id) {
        await client.query(
          `INSERT INTO community_notifications (user_id, titulo, mensaje)
           VALUES ($1,$2,$3)`,
          [targetUserId, 'Nuevo “me gusta”', `${me.usuario} ha indicado "me gusta" en: ${p.rows[0].titulo}`]
        );
      }
    }

    const count = await client.query(
      `SELECT COUNT(*)::INT AS likes FROM community_likes WHERE post_id=$1`, [id]
    );

    await client.query('COMMIT');
    res.json({ liked, likes: count.rows[0].likes });
  } catch (e) {
    await client.query('ROLLBACK');
    console.error('POST /api/community/posts/:id/like', e);
    res.status(500).json({ error: 'server_error' });
  } finally {
    client.release();
  }
});

// ====== ALIAS ADMIN SEGUROS PARA MODERACIÓN DE COMENTARIOS ======
// GET pendientes
app.get('/api/admin/comments/pendientes', async (_, res) => {
  try {
    const r = await pool.query(`
      SELECT * FROM comentarios
      WHERE estado='pendiente'
      ORDER BY fecha ASC
    `);
    res.json(r.rows);
  } catch (e) {
    console.error('Error al obtener comentarios pendientes:', e);
    res.status(500).json({ success: false });
  }
});

// PUT aprobar
app.put('/api/admin/comments/:id/aprobar', async (req, res) => {
  try {
    await pool.query(`UPDATE comentarios SET estado='aprobado' WHERE id=$1`, [req.params.id]);
    res.json({ success: true });
  } catch (e) {
    console.error('Error al aprobar comentario:', e);
    res.status(500).json({ success: false });
  }
});

// DELETE rechazar
app.delete('/api/admin/comments/:id', async (req, res) => {
  try {
    await pool.query('DELETE FROM comentarios WHERE id = $1', [req.params.id]);
    res.json({ success: true });
  } catch (e) {
    console.error('Error al eliminar comentario:', e);
    res.status(500).json({ success: false });
  }
});


// POST /posts/:id/comments
communityRouter.post('/posts/:id/comments', async (req, res) => {
  const me = req._authedUser;
  if (!me) return res.status(401).json({ error: 'auth_required' });
  const { id } = req.params;
  if (!ensureUuid(id)) return res.status(400).json({ error: 'invalid_id' });
    const { contenido } = req.body;
  if (!contenido || !String(contenido).trim()) {
    return res.status(400).json({ error: 'empty_comment' });
  }

  const client = await pool.connect();
  try {
    await client.query('BEGIN');

    const ins = await client.query(
      `INSERT INTO community_comments (post_id, user_id, contenido)
       VALUES ($1,$2,$3) RETURNING id, created_at`,
      [id, me.id, contenido]
    );

    const p = await client.query(`SELECT user_id, titulo FROM community_posts WHERE id=$1`, [id]);
    const targetUserId = p.rows?.[0]?.user_id || null;
    if (p.rowCount && targetUserId && targetUserId !== me.id) {
      await client.query(
        `INSERT INTO community_notifications (user_id, titulo, mensaje)
         VALUES ($1,$2,$3)`,
        [targetUserId, 'Nuevo comentario', `${me.usuario} ha comentado en: ${p.rows[0].titulo}`]
      );
    }

    await client.query('COMMIT');
    res.status(201).json({ ok: true, id: ins.rows[0].id, created_at: ins.rows[0].created_at });
  } catch (e) {
    await client.query('ROLLBACK');
    console.error('POST /api/community/posts/:id/comments', e);
    res.status(500).json({ error: 'server_error' });
  } finally {
    client.release();
  }
});

// POST /posts/:id/vote
communityRouter.post('/posts/:id/vote', async (req, res) => {
  const me = req._authedUser;
  if (!me) return res.status(401).json({ error: 'auth_required' });
  const { id } = req.params;
  if (!ensureUuid(id)) return res.status(400).json({ error: 'invalid_id' });
  const optIdx = parseInt(option, 10);
  if (!Number.isInteger(optIdx) || optIdx < 0) {
    return res.status(400).json({ error: 'invalid_option' });
  }

  const client = await pool.connect();
  try {
    await client.query('BEGIN');

    const p = await client.query(`SELECT tipo FROM community_posts WHERE id=$1`, [id]);
    if (!p.rowCount || p.rows[0].tipo !== 'encuesta') {
      await client.query('ROLLBACK');
      return res.status(400).json({ error: 'not_a_poll' });
    }
    const opt = await client.query(
      `SELECT 1 FROM community_poll_options WHERE post_id=$1 AND idx=$2`, [id, optIdx]
    );
    if (!opt.rowCount) {
      await client.query('ROLLBACK');
      return res.status(400).json({ error: 'option_not_found' });
    }

    await client.query(
      `INSERT INTO community_poll_votes (post_id, option_idx, user_id)
       VALUES ($1,$2,$3)
       ON CONFLICT (post_id, user_id) DO UPDATE SET option_idx=EXCLUDED.option_idx, created_at=now()`,
      [id, optIdx, me.id]
    );

    await client.query('COMMIT');
    res.json({ ok: true });
  } catch (e) {
    await client.query('ROLLBACK');
    console.error('POST /api/community/posts/:id/vote', e);
    res.status(500).json({ error: 'server_error' });
  } finally {
    client.release();
  }
});

// GET /notifications
communityRouter.get('/notifications', async (req, res) => {
  if (!req._authedUser) return res.json([]);
  try {
    const r = await pool.query(
      `SELECT id, titulo, mensaje, read, created_at
         FROM community_notifications
        WHERE user_id=$1
        ORDER BY created_at DESC
        LIMIT 50`,
      [req._authedUser.id]
    );
    res.json(r.rows);
  } catch (e) {
    console.error('GET /api/community/notifications', e);
    res.status(500).json({ error: 'server_error' });
  }
});

// POST /notifications/read
communityRouter.post('/notifications/read', async (req, res) => {
  if (!req._authedUser) return res.status(401).json({ error: 'auth_required' });
  try {
    await pool.query(
      `UPDATE community_notifications SET read = TRUE WHERE user_id = $1 AND read = FALSE`,
      [req._authedUser.id]
    );
    res.json({ ok: true });
  } catch (e) {
    console.error('POST /api/community/notifications/read', e);
    res.status(500).json({ error: 'server_error' });
  }
});

// =========================
// Opiniones por activo — ENDPOINTS LEGADOS (compat con tu front)
// Tabla: comentarios (id, propiedad, usuario, contenido, fecha, estado)
// =========================

// GET /comentarios?propiedad=HM-ESP  -> solo aprobados, orden desc
app.get("/comentarios", async (req, res) => {
  const propiedad = req.query.propiedad;
  if (!propiedad) {
    return res.status(400).json({ success: false, message: "Propiedad no especificada" });
  }
  try {
    const result = await pool.query(`
      SELECT * FROM comentarios
      WHERE propiedad = $1 AND estado = 'aprobado'
      ORDER BY fecha DESC
    `, [propiedad]);
    res.json(result.rows);
  } catch (err) {
    console.error("Error al obtener comentarios:", err);
    res.status(500).json({ success: false, message: "Error al obtener" });
  }
});

// POST /comentarios  { propiedad, usuario, contenido } -> crea 'pendiente'
app.post("/comentarios", async (req, res) => {
  const { propiedad, usuario, contenido } = req.body || {};
  if (!usuario || !contenido || !propiedad) {
    return res.status(400).json({ success: false, message: "Faltan datos" });
  }
  try {
    await pool.query(`
      INSERT INTO comentarios (propiedad, usuario, contenido)
      VALUES ($1, $2, $3)
    `, [propiedad, usuario, contenido]);
    res.json({ success: true });
  } catch (err) {
    console.error("Error al guardar comentario:", err);
    res.status(500).json({ success: false, message: "Error al guardar" });
  }
});

// GET /comentarios/pendientes  -> revisión (pendientes, asc)
app.get("/comentarios/pendientes", async (_req, res) => {
  try {
    const result = await pool.query(`
      SELECT * FROM comentarios
      WHERE estado = 'pendiente'
      ORDER BY fecha ASC
    `);
    res.json(result.rows);
  } catch (err) {
    console.error("Error al obtener comentarios pendientes:", err);
    res.status(500).json({ success: false });
  }
});

// PUT /comentarios/:id/aprobar  -> pasa a 'aprobado'
app.put("/comentarios/:id/aprobar", async (req, res) => {
  const id = req.params.id;
  try {
    await pool.query(`
      UPDATE comentarios
         SET estado = 'aprobado'
       WHERE id = $1
    `, [id]);
    res.json({ success: true });
  } catch (err) {
    console.error("Error al aprobar comentario:", err);
    res.status(500).json({ success: false });
  }
});

// DELETE /comentarios/:id  -> elimina
app.delete("/comentarios/:id", async (req, res) => {
  const id = req.params.id;
  try {
    await pool.query(`DELETE FROM comentarios WHERE id = $1`, [id]);
    res.json({ success: true });
  } catch (err) {
    console.error("Error al eliminar comentario:", err);
    res.status(500).json({ success: false });
  }
});

// GET /comentarios/usuario/:usuario  -> historial aprobados del usuario
app.get("/comentarios/usuario/:usuario", async (req, res) => {
  const { usuario } = req.params;
  try {
    const result = await pool.query(`
      SELECT * FROM comentarios
      WHERE usuario = $1 AND estado = 'aprobado'
      ORDER BY fecha DESC
    `, [usuario]);
    res.json(result.rows);
  } catch (err) {
    console.error("Error al obtener comentarios del usuario:", err);
    res.status(500).json({ success: false });
  }
});


app.use('/api/community', communityRouter);

// ===== Registro PÚBLICO de embajadores =====
app.post('/api/embajadores', async (req, res) => {
  try {
    const { nombre, email, pais } = req.body || {};
    if (!nombre || !email) {
      return res.status(400).json({ success: false, message: 'Faltan nombre o email' });
    }
    const r = await pool.query(
      `INSERT INTO admin_embajadores (nombre, email, pais)
       VALUES ($1,$2,$3)
       ON CONFLICT (email) DO NOTHING
       RETURNING id, nombre, email, pais, alta_at`,
      [nombre, email, pais || null]
    );

    if (!r.rows.length) {
      // Email ya existente → lo tratamos como “ok” con flag de duplicado
      return res.status(200).json({ success: true, duplicated: true, message: 'Ya registrado', email });
    }
    res.status(201).json({ success: true, item: r.rows[0] });
  } catch (e) {
    console.error('POST /api/embajadores', e);
    res.status(500).json({ success: false, message: 'Error al registrar embajador' });
  }
});


// =========================
// Start
// =========================
app.listen(PORT, () => {
  console.log(`✅ Servidor iniciado en http://localhost:${PORT}`);
});
