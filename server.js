// server.js — MVI + Comunidad integrada (encuestas solo admin MVI + paginación de comentarios)

const express = require('express');
const cors = require('cors');
const path = require('path');
const bcrypt = require('bcrypt');
const { Pool } = require('pg');
const jwt = require("jsonwebtoken");
const propiedades = require('./propiedades.json');

const app = express();
const PORT = process.env.PORT || 3000;

// === Conexión PostgreSQL (Render) ===
const pool = new Pool({
  connectionString: process.env.DATABASE_URL,
  ssl: { rejectUnauthorized: false }
});

// === Middleware base ===
app.use(cors());
app.use(express.static(__dirname));
app.use(express.json());

// ================================
//   CREACIÓN DE TABLAS (BOOTSTRAP)
// ================================
(async () => {
  try {
    // Usuarios base
    await pool.query(`
      CREATE TABLE IF NOT EXISTS usuarios (
        id SERIAL PRIMARY KEY,
        usuario TEXT UNIQUE NOT NULL,
        password TEXT NOT NULL,
        email TEXT NOT NULL,
        tipo TEXT DEFAULT 'Inversor'
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
        acepta_terminos BOOLEAN NOT NULL,
        acepta_cookies BOOLEAN DEFAULT false,
        fecha_consentimiento TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
        version_politica TEXT DEFAULT 'v1.0 - 2025-08-02',
        ip_usuario TEXT
      );
    `);

    // ======== Comunidad ========
    await pool.query(`
      CREATE TABLE IF NOT EXISTS community_posts (
        id SERIAL PRIMARY KEY,
        autor_id INTEGER REFERENCES usuarios(id) ON DELETE SET NULL,
        categoria TEXT NOT NULL,
        titulo TEXT NOT NULL,
        contenido TEXT NOT NULL,
        tipo TEXT NOT NULL DEFAULT 'post',
        created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
      );
    `);

    await pool.query(`
      CREATE TABLE IF NOT EXISTS community_likes (
        post_id INTEGER REFERENCES community_posts(id) ON DELETE CASCADE,
        user_id INTEGER REFERENCES usuarios(id) ON DELETE CASCADE,
        created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
        PRIMARY KEY (post_id, user_id)
      );
    `);

    await pool.query(`
      CREATE TABLE IF NOT EXISTS community_comments (
        id SERIAL PRIMARY KEY,
        post_id INTEGER REFERENCES community_posts(id) ON DELETE CASCADE,
        user_id INTEGER REFERENCES usuarios(id) ON DELETE SET NULL,
        contenido TEXT NOT NULL,
        created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
      );
    `);

    await pool.query(`
      CREATE TABLE IF NOT EXISTS community_notifications (
        id SERIAL PRIMARY KEY,
        user_id INTEGER REFERENCES usuarios(id) ON DELETE CASCADE,
        tipo TEXT,
        payload JSONB,
        created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
        read BOOLEAN NOT NULL DEFAULT FALSE
      );
    `);

    // Encuestas (opcionales)
    await pool.query(`
      CREATE TABLE IF NOT EXISTS community_polls (
        post_id INTEGER PRIMARY KEY REFERENCES community_posts(id) ON DELETE CASCADE
      );
    `);

    await pool.query(`
      CREATE TABLE IF NOT EXISTS community_poll_options (
        id SERIAL PRIMARY KEY,
        post_id INTEGER REFERENCES community_posts(id) ON DELETE CASCADE,
        text TEXT NOT NULL
      );
    `);

    await pool.query(`
      CREATE TABLE IF NOT EXISTS community_poll_votes (
        post_id INTEGER REFERENCES community_posts(id) ON DELETE CASCADE,
        option_id INTEGER REFERENCES community_poll_options(id) ON DELETE CASCADE,
        user_id INTEGER REFERENCES usuarios(id) ON DELETE CASCADE,
        created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
        PRIMARY KEY (post_id, user_id)
      );
    `);

    // Índices recomendados
    await pool.query(`CREATE INDEX IF NOT EXISTS idx_comm_posts_created ON community_posts(created_at DESC);`);
    await pool.query(`CREATE INDEX IF NOT EXISTS idx_comm_posts_cat ON community_posts(categoria);`);
    await pool.query(`CREATE INDEX IF NOT EXISTS idx_comm_comments_post ON community_comments(post_id, created_at);`);
    await pool.query(`CREATE INDEX IF NOT EXISTS idx_comm_likes_post ON community_likes(post_id);`);
    await pool.query(`CREATE INDEX IF NOT EXISTS idx_comm_poll_opt_post ON community_poll_options(post_id);`);

    console.log("✅ Tablas verificadas.");
  } catch (err) {
    console.error("❌ Error al crear tablas:", err);
  }
})();

// ================================
//   AUTH helpers (JWT + fallback)
// ================================
function verificarAdminMVI(req, res, next) {
  const usuario = req.usuario; // seteado por verificarToken
  if (usuario && usuario.username === "MVI") next();
  else res.status(403).json({ error: "Acceso denegado. Solo para el administrador MVI." });
}

function verificarToken(req, res, next) {
  const authHeader = req.headers.authorization;
  const token = authHeader?.split(" ")[1];
  if (!token) return res.status(401).json({ error: "Token no proporcionado" });

  jwt.verify(token, "CLAVE_SECRETA", (err, decoded) => {
    if (err) return res.status(403).json({ error: "Token inválido" });
    req.usuario = decoded; // { id, username, tipo }
    next();
  });
}

// Helper: usuario autenticado (JWT preferido; si no, header X-Username)
async function getAuthUser(req) {
  if (req.usuario?.id) {
    const { rows } = await pool.query(
      'SELECT id, usuario, email, tipo FROM usuarios WHERE id = $1 LIMIT 1',
      [req.usuario.id]
    );
    return rows[0] || null;
  }
  const headerUsername = req.header('X-Username');
  if (headerUsername) {
    const { rows } = await pool.query(
      'SELECT id, usuario, email, tipo FROM usuarios WHERE usuario = $1 LIMIT 1',
      [headerUsername]
    );
    return rows[0] || null;
  }
  return null;
}

// ===================================================
//                ENDPOINTS DE COMUNIDAD
//             (prefijo /api/community/*)
// ===================================================
const communityBase = '/api/community';

// Quién soy (para el frontend)
app.get(`${communityBase}/me`, async (req, res) => {
  try {
    const me = await getAuthUser(req);
    res.json(me || null);
  } catch (e) {
    console.error(e);
    res.status(500).json({ error: 'me_failed' });
  }
});

// Listar posts
app.get(`${communityBase}/posts`, async (req, res) => {
  try {
    const me = await getAuthUser(req);
    const userId = me?.id || null;

    const offset = Math.max(parseInt(req.query.offset || '0', 10), 0);
    const limit = Math.min(Math.max(parseInt(req.query.limit || '10', 10), 1), 50);
    const q = (req.query.q || '').trim();
    const cats = (req.query.cats || '').split(',').filter(Boolean);
    const sort = (req.query.sort || 'recientes');

    const whereParts = [];
    const params = [];
    let p = 1;

    if (q) {
      whereParts.push(`(p.titulo ILIKE $${p} OR p.contenido ILIKE $${p})`);
      params.push(`%${q}%`); p++;
    }
    if (cats.length) {
      whereParts.push(`p.categoria = ANY($${p})`);
      params.push(cats); p++;
    }
    const whereSQL = whereParts.length ? `WHERE ${whereParts.join(' AND ')}` : '';

    const countSQL = `SELECT COUNT(*)::INT AS total FROM community_posts p ${whereSQL}`;
    const { rows: [countRow] } = await pool.query(countSQL, params);

    const mainSQL = `
      SELECT
        p.id, p.autor_id, p.categoria, p.titulo, p.contenido, p.tipo, p.created_at,
        u.usuario AS autor,
        (SELECT COUNT(*)::INT FROM community_likes cl WHERE cl.post_id = p.id) AS likes,
        (SELECT COUNT(*)::INT FROM community_comments cc WHERE cc.post_id = p.id) AS "comentariosCount",
        CASE WHEN $${p}::INT IS NULL THEN FALSE
             ELSE EXISTS (SELECT 1 FROM community_likes x WHERE x.post_id = p.id AND x.user_id = $${p})
        END AS "likedByMe",
        CASE WHEN p.tipo = 'encuesta'
          THEN (
            SELECT COALESCE(json_agg(co.text ORDER BY co.id), '[]'::json)
            FROM community_poll_options co
            WHERE co.post_id = p.id
          )
          ELSE NULL
        END AS opciones,
        CASE WHEN p.tipo = 'encuesta'
          THEN (
            SELECT COALESCE(json_agg(vv.cnt ORDER BY vv.option_id), '[]'::json)
            FROM (
              SELECT co.id AS option_id,
                     (SELECT COUNT(*)::INT FROM community_poll_votes v WHERE v.post_id = p.id AND v.option_id = co.id) AS cnt
              FROM community_poll_options co
              WHERE co.post_id = p.id
              ORDER BY co.id
            ) vv
          )
          ELSE NULL
        END AS votos
      FROM community_posts p
      LEFT JOIN usuarios u ON u.id = p.autor_id
      ${whereSQL}
      ${sort === 'likes'
        ? 'ORDER BY likes DESC, p.created_at DESC'
        : sort === 'comentarios'
        ? 'ORDER BY "comentariosCount" DESC, p.created_at DESC'
        : 'ORDER BY p.created_at DESC'}
      LIMIT $${p+1} OFFSET $${p+2};
    `;
    const mainParams = [...params, userId, limit, offset];
    const { rows: items } = await pool.query(mainSQL, mainParams);

    res.json({ items, total: countRow?.total ?? undefined });
  } catch (e) {
    console.error(e);
    res.status(500).json({ error: 'list_failed' });
  }
});

// Obtener un post
app.get(`${communityBase}/posts/:id`, async (req, res) => {
  try {
    const me = await getAuthUser(req);
    const userId = me?.id || null;
    const id = parseInt(req.params.id, 10);

    const sql = `
      SELECT
        p.id, p.autor_id, p.categoria, p.titulo, p.contenido, p.tipo, p.created_at,
        u.usuario AS autor,
        (SELECT COUNT(*)::INT FROM community_likes cl WHERE cl.post_id = p.id) AS likes,
        (SELECT COUNT(*)::INT FROM community_comments cc WHERE cc.post_id = p.id) AS "comentariosCount",
        CASE WHEN $1::INT IS NULL THEN FALSE
             ELSE EXISTS (SELECT 1 FROM community_likes x WHERE x.post_id = p.id AND x.user_id = $1)
        END AS "likedByMe",
        CASE WHEN p.tipo = 'encuesta'
          THEN (
            SELECT COALESCE(json_agg(co.text ORDER BY co.id), '[]'::json)
            FROM community_poll_options co
            WHERE co.post_id = p.id
          )
          ELSE NULL
        END AS opciones,
        CASE WHEN p.tipo = 'encuesta'
          THEN (
            SELECT COALESCE(json_agg(vv.cnt ORDER BY vv.option_id), '[]'::json)
            FROM (
              SELECT co.id AS option_id,
                     (SELECT COUNT(*)::INT FROM community_poll_votes v WHERE v.post_id = p.id AND v.option_id = co.id) AS cnt
              FROM community_poll_options co
              WHERE co.post_id = p.id
              ORDER BY co.id
            ) vv
          )
          ELSE NULL
        END AS votos
      FROM community_posts p
      LEFT JOIN usuarios u ON u.id = p.autor_id
      WHERE p.id = $2
      LIMIT 1;
    `;
    const { rows } = await pool.query(sql, [userId, id]);
    if (!rows[0]) return res.status(404).json({ error: 'not_found' });
    res.json(rows[0]);
  } catch (e) {
    console.error(e);
    res.status(500).json({ error: 'get_failed' });
  }
});

// ======= Crear post =======
// - Requiere usuario autenticado (JWT o header X-Username).
// - Si tipo === 'encuesta' => **requiere JWT admin MVI** (no se admite X-Username para esto).
app.post(`${communityBase}/posts`, async (req, res) => {
  try {
    const me = await getAuthUser(req);
    if (!me) return res.status(401).json({ error: 'auth_required' });

    let { categoria, titulo, contenido, tipo = 'post' } = req.body || {};
    if (!categoria || !titulo || (!contenido && contenido !== '')) {
      return res.status(400).json({ error: 'missing_fields' });
    }

    const isPoll = (tipo === 'encuesta') || Array.isArray(contenido);

    if (isPoll) {
      // EXIGE JWT con username === "MVI"
      const authHeader = req.headers.authorization;
      const token = authHeader?.split(' ')[1];
      let isAdmin = false;
      if (token) {
        try {
          const dec = jwt.verify(token, 'CLAVE_SECRETA');
          isAdmin = dec?.username === 'MVI';
        } catch { isAdmin = false; }
      }
      if (!isAdmin) {
        return res.status(403).json({ error: 'solo_admin_MVI_puede_crear_encuestas' });
      }
      tipo = 'encuesta'; // forzamos tipo correcto
      if (!Array.isArray(contenido) || contenido.length < 2) {
        return res.status(400).json({ error: 'encuesta_requiere_array_opciones' });
      }
    }

    // Inserta post
    const { rows } = await pool.query(
      `INSERT INTO community_posts (autor_id, categoria, titulo, contenido, tipo)
       VALUES ($1,$2,$3,$4,$5)
       RETURNING id, autor_id, categoria, titulo, contenido, tipo, created_at`,
      [me.id, categoria, titulo, typeof contenido === 'string' ? contenido : JSON.stringify(contenido), tipo]
    );
    const post = rows[0];

    // Si es encuesta, crear estructura
    if (tipo === 'encuesta') {
      await pool.query(`INSERT INTO community_polls (post_id) VALUES ($1) ON CONFLICT DO NOTHING`, [post.id]);
      for (const op of contenido) {
        await pool.query(`INSERT INTO community_poll_options (post_id, text) VALUES ($1,$2)`, [post.id, String(op)]);
      }
    }

    // Respuesta para frontend
    post.autor = me.usuario;
    post.likes = 0;
    post.comentariosCount = 0;
    post.likedByMe = false;
    if (tipo === 'encuesta') {
      post.opciones = contenido;
      post.votos = contenido.map(() => 0);
    } else {
      post.opciones = null;
      post.votos = null;
    }

    res.status(201).json(post);
  } catch (e) {
    console.error(e);
    res.status(500).json({ error: 'create_failed' });
  }
});

// Like (toggle)
app.post(`${communityBase}/posts/:id/like`, async (req, res) => {
  try {
    const me = await getAuthUser(req);
    if (!me) return res.status(401).json({ error: 'auth_required' });

    const postId = parseInt(req.params.id, 10);

    const { rows: exist } = await pool.query(
      'SELECT 1 FROM community_likes WHERE post_id=$1 AND user_id=$2 LIMIT 1',
      [postId, me.id]
    );

    let liked;
    if (exist[0]) {
      await pool.query('DELETE FROM community_likes WHERE post_id=$1 AND user_id=$2', [postId, me.id]);
      liked = false;
    } else {
      await pool.query('INSERT INTO community_likes (post_id, user_id) VALUES ($1,$2)', [postId, me.id]);
      liked = true;
    }

    const { rows: [{ count }] } = await pool.query(
      'SELECT COUNT(*)::INT AS count FROM community_likes WHERE post_id=$1',
      [postId]
    );

    res.json({ liked, likes: count });
  } catch (e) {
    console.error(e);
    res.status(500).json({ error: 'like_failed' });
  }
});

// ======= Comentarios (con paginación opcional) =======
// - Si NO se pasan parámetros de paginación => devuelve ARRAY (compat).
// - Si se pasan `page`/`pageSize` o `offset`/`limit` => devuelve objeto { items, total, ... }.
app.get(`${communityBase}/posts/:id/comments`, async (req, res) => {
  try {
    const postId = parseInt(req.params.id, 10);

    // Detectar si el cliente pide paginación
    const hasPageParams = typeof req.query.page !== 'undefined' || typeof req.query.offset !== 'undefined';

    if (!hasPageParams) {
      // Modo legacy: devolver array completo
      const { rows } = await pool.query(`
        SELECT c.id, c.post_id, c.user_id, c.contenido, c.created_at, u.usuario AS autor
        FROM community_comments c
        LEFT JOIN usuarios u ON u.id = c.user_id
        WHERE c.post_id = $1
        ORDER BY c.created_at ASC
      `, [postId]);
      return res.json(rows);
    }

    // Modo paginado
    let page = parseInt(req.query.page || '1', 10);
    let pageSize = parseInt(req.query.pageSize || req.query.limit || '20', 10);
    if (isNaN(page) || page < 1) page = 1;
    if (isNaN(pageSize) || pageSize < 1) pageSize = 20;
    pageSize = Math.min(pageSize, 100);

    // Si offset/limit llegan, priorízalos sobre page/pageSize
    let offset = parseInt(req.query.offset || ((page - 1) * pageSize), 10);
    let limit = parseInt(req.query.limit || pageSize, 10);
    if (isNaN(offset) || offset < 0) offset = 0;
    if (isNaN(limit) || limit < 1) limit = pageSize;
    limit = Math.min(limit, 100);

    const { rows: [{ total }] } = await pool.query(
      `SELECT COUNT(*)::INT AS total FROM community_comments WHERE post_id = $1`,
      [postId]
    );
    const { rows: items } = await pool.query(`
      SELECT c.id, c.post_id, c.user_id, c.contenido, c.created_at, u.usuario AS autor
      FROM community_comments c
      LEFT JOIN usuarios u ON u.id = c.user_id
      WHERE c.post_id = $1
      ORDER BY c.created_at ASC
      LIMIT $2 OFFSET $3
    `, [postId, limit, offset]);

    const currentPage = Math.floor(offset / limit) + 1;
    const hasMore = offset + items.length < total;

    res.json({
      items,
      total,
      page: currentPage,
      pageSize: limit,
      hasMore
    });
  } catch (e) {
    console.error(e);
    res.status(500).json({ error: 'comments_failed' });
  }
});

// Crear comentario
app.post(`${communityBase}/posts/:id/comments`, async (req, res) => {
  try {
    const me = await getAuthUser(req);
    if (!me) return res.status(401).json({ error: 'auth_required' });

    const postId = parseInt(req.params.id, 10);
    const { contenido } = req.body || {};
    if (!contenido) return res.status(400).json({ error: 'missing_content' });

    const { rows } = await pool.query(`
      INSERT INTO community_comments (post_id, user_id, contenido)
      VALUES ($1,$2,$3)
      RETURNING id, post_id, user_id, contenido, created_at
    `, [postId, me.id, contenido]);

    const out = rows[0];
    out.autor = me.usuario;
    res.status(201).json(out);
  } catch (e) {
    console.error(e);
    res.status(500).json({ error: 'comment_failed' });
  }
});

// Notificaciones
app.get(`${communityBase}/notifications`, async (req, res) => {
  try {
    const me = await getAuthUser(req);
    if (!me) return res.json([]);
    const { rows } = await pool.query(
      `SELECT id, tipo, payload, created_at, read FROM community_notifications WHERE user_id=$1 ORDER BY created_at DESC LIMIT 50`,
      [me.id]
    );
    const items = rows.map(r => ({
      id: r.id,
      titulo: r.tipo || 'Actualización',
      mensaje: (r.payload && r.payload.mensaje) || '',
      created_at: r.created_at,
      read: r.read
    }));
    res.json(items);
  } catch (e) {
    console.error(e);
    res.json([]);
  }
});

// Votar en encuesta
app.post(`${communityBase}/posts/:id/vote`, async (req, res) => {
  try {
    const me = await getAuthUser(req);
    if (!me) return res.status(401).json({ error: 'auth_required' });

    const postId = parseInt(req.params.id, 10);
    const optionIndex = parseInt(req.body?.option, 10);
    if (Number.isNaN(optionIndex)) return res.status(400).json({ error: 'invalid_option' });

    const { rows: postRows } = await pool.query(
      `SELECT tipo FROM community_posts WHERE id = $1 LIMIT 1`,
      [postId]
    );
    if (!postRows[0] || postRows[0].tipo !== 'encuesta') {
      return res.status(400).json({ error: 'not_a_poll' });
    }

    const { rows: optRows } = await pool.query(
      `SELECT id FROM community_poll_options WHERE post_id=$1 ORDER BY id ASC`,
      [postId]
    );
    if (!optRows[optionIndex]) return res.status(400).json({ error: 'option_out_of_bounds' });
    const optionId = optRows[optionIndex].id;

    await pool.query(`
      INSERT INTO community_poll_votes (post_id, option_id, user_id)
      VALUES ($1,$2,$3)
      ON CONFLICT (post_id, user_id)
      DO UPDATE SET option_id = EXCLUDED.option_id, created_at = NOW()
    `, [postId, optionId, me.id]);

    const { rows: counts } = await pool.query(`
      SELECT co.id AS option_id,
             (SELECT COUNT(*)::INT FROM community_poll_votes v WHERE v.post_id=$1 AND v.option_id=co.id) AS cnt
      FROM community_poll_options co
      WHERE co.post_id=$1
      ORDER BY co.id ASC
    `, [postId]);
    res.json({ success: true, counts });
  } catch (e) {
    console.error(e);
    res.status(500).json({ error: 'vote_failed' });
  }
});

// ===================================================
//            RESTO DE ENDPOINTS EXISTENTES
// ===================================================

// === Registro de usuario ===
app.post("/register", async (req, res) => {
  const { usuario, email, password, acepta_privacidad, acepta_terminos } = req.body;
  const ip = req.ip;

  if (!acepta_privacidad || !acepta_terminos) {
    return res.status(400).json({ error: "Debes aceptar las políticas legales." });
  }

  const client = await pool.connect();
  try {
    await client.query("BEGIN");
    const hashedPassword = await bcrypt.hash(password, 10);

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

    await client.query("COMMIT");
    res.status(201).json({ message: "Registro completado con consentimiento guardado" });
  } catch (err) {
    await client.query("ROLLBACK");
    console.error("Error al registrar consentimiento:", err);
    res.status(500).json({ error: "Error interno" });
  } finally {
    client.release();
  }
});

// === Login ===
app.post('/login', async (req, res) => {
  const { usuario, password } = req.body;
  try {
    const result = await pool.query('SELECT * FROM usuarios WHERE usuario = $1', [usuario]);
    const user = result.rows[0];
    if (!user) return res.status(401).json({ success: false, message: 'Usuario o contraseña incorrectos.' });

    const valid = await bcrypt.compare(password, user.password);
    if (!valid) return res.status(401).json({ success: false, message: 'Usuario o contraseña incorrectos.' });

    const token = jwt.sign(
      { id: user.id, username: user.usuario, tipo: user.tipo },
      'CLAVE_SECRETA',
      { expiresIn: '2h' }
    );

    res.json({
      success: true,
      message: 'Inicio de sesión correcto.',
      token,
      user: { id: user.id, usuario: user.usuario, email: user.email, tipo: user.tipo }
    });
  } catch (err) {
    res.status(500).json({ success: false, message: 'Error al iniciar sesión.' });
  }
});

// === Consentimientos ===
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

    if (result.rows.length > 0 && result.rows[0].acepta_privacidad && result.rows[0].acepta_terminos) {
      res.json({ aceptado: true });
    } else {
      res.json({ aceptado: false });
    }
  } catch (error) {
    console.error('Error al comprobar consentimiento:', error);
    res.status(500).json({ error: 'Error al consultar consentimiento' });
  }
});

app.post('/api/consentimientos', async (req, res) => {
  const { usuario, acepta_privacidad, acepta_terminos } = req.body;
  try {
    const result = await pool.query('SELECT id FROM usuarios WHERE usuario = $1', [usuario]);
    if (result.rows.length === 0) return res.status(404).json({ error: "Usuario no encontrado" });

    const userId = result.rows[0].id;

    await pool.query(
      `INSERT INTO consentimientos (user_id, acepta_privacidad, acepta_terminos)
       VALUES ($1, $2, $3)`,
      [userId, acepta_privacidad, acepta_terminos]
    );

    res.status(201).json({ message: 'Consentimiento registrado correctamente' });
  } catch (error) {
    console.error("Error al registrar consentimiento:", error);
    res.status(500).json({ error: "Error al guardar el consentimiento" });
  }
});

// === Registrar inversión ===
app.post('/api/inversion', async (req, res) => {
  const { usuario, propiedad, cantidad, divisa } = req.body;
  if (!usuario || !propiedad || !cantidad || !divisa)
    return res.status(400).json({ success: false, message: "Faltan datos obligatorios." });

  try {
    await pool.query(
      'INSERT INTO inversiones (usuario, propiedad, cantidad, divisa) VALUES ($1, $2, $3, $4)',
      [usuario, propiedad, cantidad, divisa]
    );
    res.json({ success: true, message: "Inversión registrada correctamente." });
  } catch (err) {
    res.status(500).json({ success: false, message: "Error al registrar inversión." });
  }
});

// === Perfil de usuario ===
app.get('/api/perfil/:usuario', async (req, res) => {
  const usuario = req.params.usuario;
  try {
    const userResult = await pool.query('SELECT usuario, email FROM usuarios WHERE usuario = $1', [usuario]);
    if (userResult.rows.length === 0)
      return res.status(404).json({ success: false, message: 'Usuario no encontrado.' });

    const inversiones = await pool.query(
      'SELECT propiedad, cantidad, divisa, fecha FROM inversiones WHERE usuario = $1 ORDER BY fecha DESC',
      [usuario]
    );

    res.json({ success: true, user: userResult.rows[0], inversiones: inversiones.rows });
  } catch (err) {
    res.status(500).json({ success: false, message: 'Error al recuperar perfil.' });
  }
});

// === Panel admin: ver usuarios e inversiones ===
app.get('/api/admin/datos', async (req, res) => {
  const admin = req.query.admin;
  if (admin !== 'MVI') return res.status(403).json({ success: false, message: "Acceso denegado." });

  try {
    const usuarios = await pool.query('SELECT usuario, email FROM usuarios');
    const inversiones = await pool.query('SELECT usuario, propiedad, cantidad, divisa, fecha FROM inversiones ORDER BY fecha DESC');
    res.json({ success: true, usuarios: usuarios.rows, inversiones: inversiones.rows });
  } catch (err) {
    res.status(500).json({ success: false, message: "Error al obtener datos." });
  }
});

// === Eliminar usuario (por nombre) ===
app.delete('/api/admin/usuarios/por-nombre/:usuario', async (req, res) => {
  const usuario = req.params.usuario;
  if (!usuario || usuario === "MVI") {
    return res.status(400).json({ message: "No permitido o usuario inválido." });
  }

  try {
    await pool.query('DELETE FROM inversiones WHERE usuario = $1', [usuario]);
    await pool.query('DELETE FROM usuarios WHERE usuario = $1', [usuario]);
    res.json({ message: `Usuario "${usuario}" eliminado correctamente.` });
  } catch (err) {
    console.error("Error al eliminar usuario:", err);
    res.status(500).json({ message: "Error al eliminar usuario." });
  }
});

// === Endpoint administrativo general ===
app.get('/api/admin/data', async (req, res) => {
  try {
    const usuarios = await pool.query('SELECT usuario, email FROM usuarios');
    const inversiones = await pool.query('SELECT * FROM inversiones');
    res.json({ usuarios: usuarios.rows, inversiones: inversiones.rows });
  } catch (err) {
    res.status(500).json({ message: "Error interno del servidor" });
  }
});

// === Comentarios (propiedades) ===
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

app.put("/comentarios/:id/aprobar", async (req, res) => {
  const id = req.params.id;
  try {
    await pool.query(`UPDATE comentarios SET estado = 'aprobado' WHERE id = $1`, [id]);
    res.json({ success: true });
  } catch (err) {
    console.error("Error al aprobar comentario:", err);
    res.status(500).json({ success: false });
  }
});

app.get("/comentarios/pendientes", async (req, res) => {
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

app.post("/comentarios", async (req, res) => {
  const { propiedad, usuario, contenido } = req.body;
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

// (Arreglado) Actualizar perfil (sin campo descripcion en esquema)
app.post("/api/actualizar-perfil", async (req, res) => {
  const { original, nuevoUsuario } = req.body;
  if (!original || !nuevoUsuario) return res.status(400).json({ success: false, message: "Faltan datos" });

  try {
    const result = await pool.query(
      `UPDATE usuarios SET usuario = $2 WHERE usuario = $1`,
      [original, nuevoUsuario]
    );
    if (result.rowCount > 0) res.json({ success: true });
    else res.json({ success: false, message: "No se actualizó ningún perfil." });
  } catch (err) {
    console.error("Error en actualizar-perfil:", err);
    res.status(500).json({ success: false, message: "Error en la base de datos" });
  }
});

// === Favoritos ===
app.post('/api/favoritos', async (req, res) => {
  const { usuario, propiedadId } = req.body;
  if (!usuario || !propiedadId)
    return res.status(400).json({ success: false, message: "Faltan datos." });

  try {
    const existe = await pool.query(
      'SELECT 1 FROM favoritos WHERE usuario = $1 AND propiedad = $2',
      [usuario, propiedadId]
    );
    if (existe.rows.length > 0)
      return res.status(409).json({ success: false, message: "Ya es favorito." });

    await pool.query(
      'INSERT INTO favoritos (usuario, propiedad) VALUES ($1, $2)',
      [usuario, propiedadId]
    );
    res.json({ success: true, message: "Añadido a favoritos." });
  } catch (err) {
    console.error("Error añadiendo favorito:", err);
    res.status(500).json({ success: false });
  }
});

app.delete('/api/favoritos', async (req, res) => {
  const { usuario, propiedadId } = req.body;
  if (!usuario || !propiedadId)
    return res.status(400).json({ success: false, message: "Faltan datos." });

  try {
    await pool.query(
      'DELETE FROM favoritos WHERE usuario = $1 AND propiedad = $2',
      [usuario, propiedadId]
    );
    res.json({ success: true, message: "Favorito eliminado." });
  } catch (err) {
    console.error("Error eliminando favorito:", err);
    res.status(500).json({ success: false });
  }
});

app.get('/api/favoritos/:usuario', async (req, res) => {
  const { usuario } = req.params;
  try {
    const result = await pool.query(
      'SELECT propiedad FROM favoritos WHERE usuario = $1',
      [usuario]
    );
    const favoritos = result.rows.map(row => row.propiedad);
    res.json(favoritos);
  } catch (err) {
    console.error("Error obteniendo favoritos:", err);
    res.status(500).json({ success: false });
  }
});

// === Propiedades mock (JSON) ===
app.get('/api/propiedades/:id', (req, res) => {
  const prop = propiedades.find(p => p.id === req.params.id);
  if (!prop) return res.status(404).json({ success: false });
  res.json(prop);
});

// === Embajadores ===
app.post('/api/embajadores', async (req, res) => {
  const { email, acepta_privacidad, acepta_terminos } = req.body;
  const ip = req.ip;

  if (!email || !acepta_privacidad || !acepta_terminos) {
    return res.status(400).json({ error: "Faltan datos o no se aceptaron los términos." });
  }

  try {
    await pool.query(`
      INSERT INTO usuarios (usuario, email, password, tipo)
      VALUES ($1, $1, '', 'Embajador')
      ON CONFLICT (usuario) DO NOTHING
    `, [email]);

    const result = await pool.query(`SELECT id FROM usuarios WHERE usuario = $1`, [email]);
    const userId = result.rows[0].id;

    await pool.query(`
      INSERT INTO consentimientos (user_id, acepta_privacidad, acepta_terminos, ip_usuario)
      VALUES ($1, $2, $3, $4)
    `, [userId, true, true, ip]);

    res.status(201).json({ message: "Embajador registrado correctamente" });
  } catch (error) {
    console.error("Error al registrar embajador:", error);
    res.status(500).json({ error: "Error interno del servidor" });
  }
});

app.get('/api/admin/embajadores', async (req, res) => {
  const admin = req.query.admin;
  if (admin !== 'MVI') return res.status(403).json({ error: "Acceso denegado" });

  try {
    const result = await pool.query(`
      SELECT u.email, c.acepta_privacidad, c.acepta_terminos, c.fecha_consentimiento, c.version_politica, c.ip_usuario
      FROM usuarios u
      JOIN consentimientos c ON u.id = c.user_id
      WHERE u.tipo = 'Embajador'
      ORDER BY c.fecha_consentimiento DESC
    `);

    res.json({ success: true, datos: result.rows });
  } catch (err) {
    console.error("Error al obtener embajadores:", err);
    res.status(500).json({ success: false, error: "Error interno del servidor" });
  }
});

// === Raíz ===
app.get('/', (req, res) => {
  res.send("Backend MVI activo");
});

// === Arranque ===
app.listen(PORT, () => {
  console.log(`✅ Servidor iniciado en http://localhost:${PORT}`);
});
