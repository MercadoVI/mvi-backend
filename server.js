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

// Cargar .env en desarrollo; en producción (Render) ya usa process.env
try { require('dotenv').config(); } catch (e) {
  console.warn('dotenv no disponible; usando variables del entorno');
}

// Google Auth
const { OAuth2Client } = require('google-auth-library');
const oauthClient = new OAuth2Client();

// ✅ Client IDs permitidos (Web + iOS)
const GOOGLE_WEB_CLIENT_ID =
  process.env.GOOGLE_WEB_CLIENT_ID ||
  '329044944531-opeo9m7r3q4e1uf22lhll0atftfv0qp9.apps.googleusercontent.com';

const GOOGLE_IOS_CLIENT_ID =
  process.env.GOOGLE_IOS_CLIENT_ID ||
  '329044944531-opeo9m7r3q4e1uf22lhll0atftfv0qp9.apps.googleusercontent.com'; // <-- pon aquí el iOS si es distinto

const GOOGLE_ALLOWED_CLIENT_IDS = [
  GOOGLE_WEB_CLIENT_ID,
  GOOGLE_IOS_CLIENT_ID
].filter(Boolean);

// Usa siempre la clave fuerte de JWT desde el entorno
const JWT_SECRET = process.env.JWT_SECRET;
if (!JWT_SECRET) throw new Error('Falta JWT_SECRET en variables de entorno');

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
// ===== Cache estática optimizada (reemplaza tu express.static actual) =====
const compression = require('compression');   // <— arriba del todo junto a otros require
app.use(compression());                       // GZIP/Brotli (si está disponible en el host)

const ONE_YEAR = 31536000; // en segundos
const FIVE_MIN = 300;

app.use(express.static(__dirname, {
  etag: true,
  lastModified: true,
  // maxAge por defecto (por si no coincide ningún patrón)
  maxAge: FIVE_MIN * 1000,
  setHeaders: (res, filePath) => {
    // 1) HTML: corto y revalidable
    if (/\.html?$/i.test(filePath)) {
      res.setHeader('Cache-Control', 'public, max-age=300, must-revalidate');
      return;
    }
    // 2) Estáticos fingerprintables: 1 año + immutable
    if (/\.(?:js|css|png|jpe?g|gif|svg|webp|ico|woff2?)$/i.test(filePath)) {
      res.setHeader('Cache-Control', `public, max-age=${ONE_YEAR}, immutable`);
      return;
    }
    // 3) Fallback (JSON u otros): corto
    res.setHeader('Cache-Control', 'public, max-age=300, must-revalidate');
  }
}));
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

    await pool.query(`ALTER TABLE usuarios ADD COLUMN IF NOT EXISTS cartera_publica BOOLEAN NOT NULL DEFAULT FALSE;`);
    await pool.query(`
    ALTER TABLE usuarios
      ADD COLUMN IF NOT EXISTS google_id TEXT UNIQUE,
      ADD COLUMN IF NOT EXISTS picture TEXT,
      ADD COLUMN IF NOT EXISTS email_verified BOOLEAN DEFAULT FALSE,
      ADD COLUMN IF NOT EXISTS provider TEXT,
      ADD COLUMN IF NOT EXISTS public_google_avatar BOOLEAN NOT NULL DEFAULT TRUE;
    ALTER TABLE usuarios
      ADD COLUMN IF NOT EXISTS firebase_uid TEXT UNIQUE;

    DO $$
    BEGIN
      IF EXISTS (
        SELECT 1 FROM information_schema.columns
        WHERE table_name='usuarios' AND column_name='password'
      ) THEN
        -- permitir cuentas OAuth sin contraseña
        ALTER TABLE usuarios ALTER COLUMN password DROP NOT NULL;
      END IF;
    END$$;
    `);

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

    // 1) Borrar duplicados, conservando la inversión más reciente por (usuario, propiedad)
    await pool.query(`
  WITH ranked AS (
    SELECT ctid,
           row_number() OVER (
             PARTITION BY usuario, propiedad
             ORDER BY fecha DESC, id DESC
           ) AS rn
    FROM inversiones
  )
  DELETE FROM inversiones i
  USING ranked r
  WHERE i.ctid = r.ctid AND r.rn > 1;
`);

    // 2) Ahora sí, crear índice único
    await pool.query(`
  DO $$
  BEGIN
    IF NOT EXISTS (
      SELECT 1 FROM pg_indexes
      WHERE schemaname = 'public' AND indexname = 'ux_inversion_usuario_prop'
    ) THEN
      EXECUTE 'CREATE UNIQUE INDEX ux_inversion_usuario_prop ON inversiones(usuario, propiedad)';
    END IF;
  END $$;
`);


    await pool.query(`
      CREATE UNIQUE INDEX IF NOT EXISTS ux_inversion_usuario_prop
      ON inversiones(usuario, propiedad);
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

    // ... dentro de async function runMigrations() { ... } en server.js

    // ⬇️ pega esto después de crear las tablas de comunidad (likes/comments/polls) y antes del console.log final
    await pool.query(`
     -- 🔧 Normalización: asegurar post_id como TEXT en tablas hijas y quitar FKs legados
      DO $$
      DECLARE r record;
      BEGIN
        -- 1) Drop todos los FKs sobre post_id en tablas hijas (si existen)
        FOR r IN
          SELECT c.conname,
                format('%I', t.relname) AS tbl
          FROM pg_constraint c
          JOIN pg_class t ON t.oid = c.conrelid
          JOIN pg_attribute a ON a.attrelid = c.conrelid AND a.attnum = ANY(c.conkey)
          WHERE c.contype = 'f'
            AND a.attname = 'post_id'
            AND t.relname IN ('community_likes','community_comments','community_poll_options','community_poll_votes')
        LOOP
          EXECUTE format('ALTER TABLE %s DROP CONSTRAINT IF EXISTS %I', r.tbl, r.conname);
        END LOOP;

        -- 2) Forzar post_id -> TEXT sólo si aún no es TEXT
        IF EXISTS (SELECT 1 FROM information_schema.columns WHERE table_name='community_likes' AND column_name='post_id' AND data_type <> 'text') THEN
          ALTER TABLE community_likes       ALTER COLUMN post_id TYPE text USING post_id::text;
        END IF;
        IF EXISTS (SELECT 1 FROM information_schema.columns WHERE table_name='community_comments' AND column_name='post_id' AND data_type <> 'text') THEN
          ALTER TABLE community_comments    ALTER COLUMN post_id TYPE text USING post_id::text;
        END IF;
        IF EXISTS (SELECT 1 FROM information_schema.columns WHERE table_name='community_poll_options' AND column_name='post_id' AND data_type <> 'text') THEN
          ALTER TABLE community_poll_options ALTER COLUMN post_id TYPE text USING post_id::text;
        END IF;
        IF EXISTS (SELECT 1 FROM information_schema.columns WHERE table_name='community_poll_votes' AND column_name='post_id' AND data_type <> 'text') THEN
          ALTER TABLE community_poll_votes  ALTER COLUMN post_id TYPE text USING post_id::text;
        END IF;
      END$$;

      -- 3) Índice único anti-duplicados en likes
      CREATE UNIQUE INDEX IF NOT EXISTS ux_community_likes_post_user ON community_likes(post_id, user_id);

      -- 4) Índices útiles para rendimiento (opcional pero recomendable)
      CREATE INDEX IF NOT EXISTS ix_comments_post ON community_comments(post_id);
      CREATE INDEX IF NOT EXISTS ix_likes_post    ON community_likes(post_id);
      `);

    await pool.query(`
      CREATE UNIQUE INDEX IF NOT EXISTS ux_community_likes_post_user ON community_likes(post_id, user_id);
    `);
    // === PREMIUM & REFERIDOS (migraciones) ===
    await pool.query(`
  ALTER TABLE usuarios
    ADD COLUMN IF NOT EXISTS premium_months_active  INTEGER NOT NULL DEFAULT 0,
    ADD COLUMN IF NOT EXISTS premium_months_pending INTEGER NOT NULL DEFAULT 0,
    ADD COLUMN IF NOT EXISTS inviter_code           TEXT;

  CREATE TABLE IF NOT EXISTS invitaciones (
    id SERIAL PRIMARY KEY,
    codigo TEXT UNIQUE NOT NULL,
    emisor TEXT NOT NULL,
    receptor TEXT,
    estado TEXT NOT NULL DEFAULT 'generado', -- generado | reclamado | activado | rechazado
    meses_otorgables INTEGER NOT NULL DEFAULT 1,
    creado_en TIMESTAMP DEFAULT now(),
    reclamado_en TIMESTAMP,
    activado_en TIMESTAMP
  );

  CREATE TABLE IF NOT EXISTS invitaciones_contador (
    usuario TEXT PRIMARY KEY,
    invitaciones_emitidas INTEGER NOT NULL DEFAULT 0, -- máx. 6
    meses_acumulados INTEGER NOT NULL DEFAULT 0       -- máx. 5 (ajustable)
  );
`);

    // 🔧 Normalización de community_notifications (soportar esquemas antiguos)
    await pool.query(`
DO $$
BEGIN
  -- titulo
  IF NOT EXISTS (
    SELECT 1 FROM information_schema.columns
    WHERE table_name='community_notifications' AND column_name='titulo'
  ) THEN
    ALTER TABLE community_notifications ADD COLUMN titulo TEXT;
    -- poblar desde 'tipo' si existe; si no, valor por defecto
    IF EXISTS (
      SELECT 1 FROM information_schema.columns
      WHERE table_name='community_notifications' AND column_name='tipo'
    ) THEN
      UPDATE community_notifications
         SET titulo = COALESCE(titulo, tipo::text, 'Notificación');
    ELSE
      UPDATE community_notifications
         SET titulo = COALESCE(titulo, 'Notificación');
    END IF;
  END IF;

  -- mensaje
  IF NOT EXISTS (
    SELECT 1 FROM information_schema.columns
    WHERE table_name='community_notifications' AND column_name='mensaje'
  ) THEN
    ALTER TABLE community_notifications ADD COLUMN mensaje TEXT;
    -- intentar migrar desde columnas antiguas comunes
    IF EXISTS (
      SELECT 1 FROM information_schema.columns
      WHERE table_name='community_notifications' AND column_name='texto'
    ) THEN
      UPDATE community_notifications
         SET mensaje = COALESCE(mensaje, texto::text);
    ELSIF EXISTS (
      SELECT 1 FROM information_schema.columns
      WHERE table_name='community_notifications' AND column_name='descripcion'
    ) THEN
      UPDATE community_notifications
         SET mensaje = COALESCE(mensaje, descripcion::text);
    ELSE
      UPDATE community_notifications
         SET mensaje = COALESCE(mensaje, '');
    END IF;
  END IF;

  -- "read"
  IF NOT EXISTS (
    SELECT 1 FROM information_schema.columns
    WHERE table_name='community_notifications' AND column_name='read'
  ) THEN
    ALTER TABLE community_notifications ADD COLUMN "read" BOOLEAN NOT NULL DEFAULT FALSE;
  END IF;

  -- created_at
  IF NOT EXISTS (
    SELECT 1 FROM information_schema.columns
    WHERE table_name='community_notifications' AND column_name='created_at'
  ) THEN
    ALTER TABLE community_notifications ADD COLUMN created_at TIMESTAMPTZ NOT NULL DEFAULT now();
  END IF;
END$$;

-- Índice útil
CREATE INDEX IF NOT EXISTS ix_notifs_user ON community_notifications(user_id, "read", created_at DESC);

CREATE TABLE IF NOT EXISTS user_push_tokens (
  user_id   INTEGER NOT NULL REFERENCES usuarios(id) ON DELETE CASCADE,
  token     TEXT    NOT NULL,
  platform  TEXT,
  created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
  last_seen  TIMESTAMPTZ NOT NULL DEFAULT now(),
  PRIMARY KEY (user_id, token)
);

CREATE INDEX IF NOT EXISTS ix_push_tokens_user ON user_push_tokens(user_id);

-- Control de difusiones (idempotencia por clave)
CREATE TABLE IF NOT EXISTS notif_broadcast (
  bkey TEXT PRIMARY KEY,
  created_at TIMESTAMPTZ NOT NULL DEFAULT now()
);


`);

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
// Genera un username único a partir de un nombre base (email/local-part)
async function uniqueUsername(client, base) {
  const norm = (base || 'user').toLowerCase().replace(/[^a-z0-9_-]/g, '').slice(0, 20) || 'user';
  const exists = async (u) => {
    const r = await client.query(`SELECT 1 FROM usuarios WHERE usuario=$1 LIMIT 1`, [u]);
    return r.rowCount > 0;
  };

  if (!await exists(norm)) return norm;

  // prueba sufijos numéricos
  for (let i = 1; i <= 50; i++) {
    const candidate = `${norm}${i}`;
    if (!await exists(candidate)) return candidate;
  }

  // fallback aleatorio
  while (true) {
    const candidate = `${norm}-${Math.floor(1000 + Math.random() * 9000)}`;
    if (!await exists(candidate)) return candidate;
  }
}

function verificarAdminMVI(req, res, next) {
  const usuario = req.usuario;
  if (usuario && usuario.username === 'MVI') return next();
  return res.status(403).json({ error: 'Acceso denegado. Solo para el administrador.' });
}

function verificarToken(req, res, next) {
  const authHeader = req.headers.authorization;
  const token = authHeader?.split(' ')[1];
  if (!token) return res.status(401).json({ error: 'Token no proporcionado' });
  jwt.verify(token, JWT_SECRET, (err, decoded) => {
    if (err) return res.status(403).json({ error: 'Token inválido' });
    req.usuario = decoded; // { id, username, tipo }
    next();
  });
}

// ====== REFERRALS: helpers de codificación segura (letra→número) ======
function encodeUsernameToNumbers(username) {
  const map = {
    A: '01', B: '02', C: '03', D: '04', E: '05', F: '06', G: '07', H: '08', I: '09',
    J: '10', K: '11', L: '12', M: '13', N: '14', O: '15', P: '16', Q: '17', R: '18',
    S: '19', T: '20', U: '21', V: '22', W: '23', X: '24', Y: '25'
    , Z: '26'
  };
  return String(username || '')
    .toUpperCase()
    .replace(/[^A-Z0-9]/g, '')       // solo A-Z y 0-9
    .split('')
    .map(ch => map[ch] || ch)        // letras → números; dígitos quedan igual
    .join('')
    .slice(0, 14);                    // límite para no hacer códigos larguísimos
}

function buildReferralCodeFromUser(username) {
  const encoded = encodeUsernameToNumbers(username);
  // bloque aleatorio para evitar colisiones
  const rand = Math.random().toString(36).slice(2, 7).toUpperCase();
  // sin el nombre literal, sólo prefijo + parte codificada + aleatorio
  return `RI-${encoded}-${rand}`;
}



// =========================
// Rutas misceláneas
// =========================
app.get('/healthz', (_, res) => res.json({ ok: true }));
app.get('/', (_, res) => res.send('Backend RI activo'));

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

    const token = jwt.sign(
      { id: user.id, username: user.usuario, tipo: user.tipo },
      JWT_SECRET,
      { expiresIn: '30d' }
    );

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

app.post('/auth/google/idtoken', async (req, res) => {
  try {
    const { credential, acepta_privacidad, acepta_terminos } = req.body || {};
    if (!credential) return res.status(400).json({ error: 'missing_credential' });

    // 1) Verificar ID Token con Google
    const ticket = await oauthClient.verifyIdToken({
      idToken: credential,
      audience: GOOGLE_ALLOWED_CLIENT_IDS // ✅ acepta web + ios
    });

    const payload = ticket.getPayload(); // sub, email, email_verified, name, picture...
    const googleId = payload.sub;
    const email = String(payload.email || '').toLowerCase();
    const emailVerified = !!payload.email_verified;
    const picture = payload.picture || null;
    const nombre = payload.name || (email ? email.split('@')[0] : `user_${googleId.slice(-6)}`);
    const suggested = ((email && email.split('@')[0]) || nombre || `user_${googleId.slice(-6)}`);
    const client = await pool.connect();
    const username = await uniqueUsername(client, suggested);

    let user;
    try {
      await client.query('BEGIN');

      // 2a) buscar por google_id
      const byGid = await client.query(`SELECT * FROM usuarios WHERE google_id=$1 LIMIT 1`, [googleId]);
      user = byGid.rows[0];

      // 2b) si no existe por google_id, intenta por email para vincular cuenta previa
      if (!user && email) {
        const byEmail = await client.query(`SELECT * FROM usuarios WHERE LOWER(email)=LOWER($1) LIMIT 1`, [email]);
        user = byEmail.rows[0];
        if (user && !user.google_id) {
          await client.query(`
            UPDATE usuarios
               SET google_id=$1, picture=$2, email_verified=$3, provider='google'
             WHERE id=$4
          `, [googleId, picture, emailVerified, user.id]);
          user = (await client.query(`SELECT * FROM usuarios WHERE id=$1`, [user.id])).rows[0];
        }
      }

      // 2c) si no existe, crear “Inversor” sin contraseña
      if (!user) {
        const ins = await client.query(`
          INSERT INTO usuarios (usuario, email, password, tipo, descripcion, google_id, picture, email_verified, provider)
          VALUES ($1,$2,NULL,'Inversor',NULL,$3,$4,$5,'google')
          RETURNING *;
        `, [username, email || `${googleId}@noemail.local`, googleId, picture, emailVerified]);
        user = ins.rows[0];

        // guardar consentimiento si ya viene marcado desde el front
        if (acepta_privacidad && acepta_terminos) {
          await client.query(
            `INSERT INTO consentimientos (user_id, acepta_privacidad, acepta_terminos, ip_usuario)
             VALUES ($1,$2,$3,$4)`,
            [user.id, true, true, req.ip]
          );
        }
      }

      await client.query('COMMIT');
    } catch (e) {
      await client.query('ROLLBACK');
      console.error('google idtoken error', e);
      return res.status(500).json({ error: 'server_error' });
    } finally {
      client.release();
    }

    // 3) emitir tu JWT (mismo formato que en /login)
    const token = jwt.sign(
      { id: user.id, username: user.usuario, tipo: user.tipo },
      JWT_SECRET,
      { expiresIn: '30d' }
    );

    // 4) comprobar si ya hay consentimiento registrado
    const cons = await pool.query(`
      SELECT 1
        FROM consentimientos c
       WHERE c.user_id=$1 AND c.acepta_privacidad AND c.acepta_terminos
       ORDER BY c.fecha_consentimiento DESC
       LIMIT 1
    `, [user.id]);

    res.json({
      success: true,
      token,
      user: { id: user.id, usuario: user.usuario, email: user.email, tipo: user.tipo, picture: user.picture },
      legal_ok: cons.rows.length > 0
    });
  } catch (err) {
    console.error('verifyIdToken', err);
    res.status(401).json({ error: 'invalid_google_token' });
  }
});

// Requiere que definas FIREBASE_API_KEY en Render (la misma del cliente)
const FIREBASE_API_KEY = 'AIzaSyDLyTsx_lg6eU65nkL1faPH_axE_mG6NLo';

app.post('/auth/firebase/idtoken', async (req, res) => {
  try {
    const { idToken } = req.body || {};
    if (!idToken) {
      return res.status(400).json({ error: 'missing_id_token' });
    }
    if (!FIREBASE_API_KEY) {
      return res.status(500).json({ error: 'server_misconfig', details: 'Falta FIREBASE_API_KEY' });
    }

    // ✅ Verificación correcta del ID token de Firebase
    const resp = await fetch(
      `https://identitytoolkit.googleapis.com/v1/accounts:lookup?key=${encodeURIComponent(FIREBASE_API_KEY)}`,
      {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ idToken })
      }
    );
    const data = await resp.json();

    if (!resp.ok || !data?.users?.length) {
      return res.status(401).json({
        error: 'invalid_token',
        details: data?.error?.message || 'accounts:lookup failed'
      });
    }

    // Usuario Firebase
    const u = data.users[0];
    const firebaseUid = u.localId;
    const email = (u.email || `${firebaseUid}@firebase.local`).toLowerCase();
    const nombre = u.displayName || email.split('@')[0];
    const picture = u.photoUrl || null;

    // Vincula/crea en tu BD
    const r = await pool.query(
      'SELECT * FROM usuarios WHERE email=$1 OR firebase_uid=$2 LIMIT 1',
      [email, firebaseUid]
    );
    let user = r.rows[0];

    if (!user) {
      const ins = await pool.query(
        `INSERT INTO usuarios (usuario, email, tipo, firebase_uid, provider, picture)
         VALUES ($1,$2,'Inversor',$3,'firebase',$4)
         RETURNING *`,
        [nombre, email, firebaseUid, picture]
      );
      user = ins.rows[0];
    } else if (!user.firebase_uid) {
      // si ya existía por email, guardamos el UID
      await pool.query(
        'UPDATE usuarios SET firebase_uid=$1, provider=$2 WHERE id=$3',
        [firebaseUid, 'firebase', user.id]
      );
      const r2 = await pool.query('SELECT * FROM usuarios WHERE id=$1', [user.id]);
      user = r2.rows[0];
    }

    const token = jwt.sign(
      { id: user.id, username: user.usuario, tipo: user.tipo },
      JWT_SECRET,
      { expiresIn: '30d' }
    );


    return res.json({
      success: true,
      token,
      user: { id: user.id, usuario: user.usuario, email: user.email, tipo: user.tipo, picture }
    });
  } catch (err) {
    console.error('Error en /auth/firebase/idtoken', err);
    return res.status(401).json({ error: 'invalid_token' });
  }
});


// === REFERIDOS: generar código (usuario logueado) — NUEVA VERSIÓN CIFRADA ===
app.post('/api/invitaciones/generar', verificarToken, async (req, res) => {
  const client = await pool.connect();
  try {
    const emisor = req.usuario.username; // viene del JWT
    // límite de 6 invitaciones emitidas
    const r0 = await client.query(
      'SELECT invitaciones_emitidas FROM invitaciones_contador WHERE usuario=$1',
      [emisor]
    );
    const emitidas = r0.rows[0]?.invitaciones_emitidas || 0;
    if (emitidas >= 6) {
      return res.status(400).json({ success: false, message: 'Máximo 6 invitaciones.' });
    }

    // genera código con usuario codificado (letra→número) + aleatorio
    let codigo;
    let intentos = 0;
    while (true) {
      intentos++;
      codigo = buildReferralCodeFromUser(emisor);
      try {
        await client.query('BEGIN');
        await client.query(
          'INSERT INTO invitaciones (codigo, emisor, meses_otorgables) VALUES ($1,$2,$3)',
          [codigo, emisor, 1]
        );
        if (r0.rows.length) {
          await client.query(
            'UPDATE invitaciones_contador SET invitaciones_emitidas = invitaciones_emitidas + 1 WHERE usuario=$1',
            [emisor]
          );
        } else {
          await client.query(
            'INSERT INTO invitaciones_contador (usuario, invitaciones_emitidas, meses_acumulados) VALUES ($1, 1, 0)',
            [emisor]
          );
        }
        await client.query('COMMIT');
        break; // ok
      } catch (e) {
        await client.query('ROLLBACK');
        // 23505 = unique_violation; reintenta con otro aleatorio
        if (e && e.code === '23505' && intentos < 5) continue;
        console.error('generar invitación (código):', e);
        return res.status(500).json({ success: false, message: 'server_error' });
      }
    }

    const linkBase = process.env.PUBLIC_APP_URL || 'https://realtyinvestor.eu';
    const link = `${linkBase}/entrar.html?ref=${encodeURIComponent(codigo)}`;
    res.json({ success: true, codigo, link });
  } catch (e) {
    console.error('generar invitación', e);
    return res.status(500).json({ success: false, message: 'server_error' });
  } finally {
    client.release();
  }
});

// === REFERIDOS: reclamar código (tras registro) ===
// body: { receptor: "nuevoUsuario", refCode: "RI-..." }
app.post('/api/invitaciones/reclamar', async (req, res) => {
  try {
    const { receptor, refCode } = req.body || {};
    if (!receptor || !refCode) return res.status(400).json({ success: false, message: 'Datos incompletos.' });

    const inv = await pool.query('SELECT * FROM invitaciones WHERE codigo=$1', [refCode]);
    const row = inv.rows[0];
    if (!row) return res.status(404).json({ success: false, message: 'Código no válido.' });
    if (row.estado !== 'generado') return res.status(400).json({ success: false, message: 'Código ya usado.' });
    if (row.emisor === receptor) return res.status(400).json({ success: false, message: 'No puedes invitarte a ti mismo.' });

    // Límite receptor: máx. 5 meses acumulables
    const cR = await pool.query('SELECT meses_acumulados FROM invitaciones_contador WHERE usuario=$1', [receptor]);
    const mesesRec = cR.rows[0]?.meses_acumulados || 0;
    if (mesesRec >= 5) return res.status(400).json({ success: false, message: 'Máximo 5 meses acumulables por invitado.' });

    await pool.query('UPDATE invitaciones SET estado=$1, receptor=$2, reclamado_en=now() WHERE codigo=$3',
      ['reclamado', receptor, refCode]);
    await pool.query('UPDATE usuarios SET inviter_code=$1 WHERE usuario=$2', [refCode, receptor]);

    await pool.query('UPDATE usuarios SET premium_months_pending=premium_months_pending+1 WHERE usuario=$1', [row.emisor]);
    await pool.query('UPDATE usuarios SET premium_months_pending=premium_months_pending+1 WHERE usuario=$1', [receptor]);

    if (cR.rows.length) {
      await pool.query('UPDATE invitaciones_contador SET meses_acumulados=meses_acumulados+1 WHERE usuario=$1', [receptor]);
    } else {
      await pool.query('INSERT INTO invitaciones_contador(usuario,invitaciones_emitidas,meses_acumulados) VALUES($1,0,1)', [receptor]);
    }

    res.json({ success: true, message: 'Invitación reclamada. Meses pendientes añadidos.' });
  } catch (e) {
    console.error('reclamar invitación', e);
    res.status(500).json({ success: false, message: 'server_error' });
  }
});

// === REFERIDOS: activar (solo admin MVI) ===
// body: { codigo: "RI-..." }
app.post('/api/invitaciones/activar', verificarToken, async (req, res) => {
  try {
    if (req.usuario.username !== 'MVI') return res.status(403).json({ success: false, message: 'Solo admin' });
    const { codigo } = req.body || {};
    const inv = await pool.query('SELECT * FROM invitaciones WHERE codigo=$1', [codigo]);
    const row = inv.rows[0];
    if (!row) return res.status(404).json({ success: false, message: 'No existe la invitación' });
    if (row.estado !== 'reclamado') return res.status(400).json({ success: false, message: 'La invitación no está reclamada' });

    await pool.query('BEGIN');
    await pool.query(
      'UPDATE usuarios SET premium_months_pending=premium_months_pending-1, premium_months_active=premium_months_active+1 WHERE usuario=$1',
      [row.emisor]
    );
    await pool.query(
      'UPDATE usuarios SET premium_months_pending=premium_months_pending-1, premium_months_active=premium_months_active+1 WHERE usuario=$1',
      [row.receptor]
    );
    await pool.query('UPDATE invitaciones SET estado=$1, activado_en=now() WHERE id=$2', ['activado', row.id]);
    await pool.query('COMMIT');

    res.json({ success: true, message: 'Meses activados para emisor y receptor.' });
  } catch (e) {
    await pool.query('ROLLBACK').catch(() => { });
    console.error('activar invitación', e);
    res.status(500).json({ success: false, message: 'server_error' });
  }
});

// === ADMIN: listar invitaciones por estado ===
// GET /api/invitaciones/listar?estado=reclamado
app.get('/api/invitaciones/listar', verificarToken, async (req, res) => {
  try {
    if (req.usuario.username !== 'MVI') return res.status(403).json({ success: false, message: 'Solo admin' });
    const estado = req.query.estado || 'reclamado';
    const r = await pool.query('SELECT * FROM invitaciones WHERE estado=$1 ORDER BY reclamado_en DESC NULLS LAST, creado_en DESC', [estado]);
    res.json({ success: true, data: r.rows });
  } catch (e) {
    console.error('listar invitaciones', e);
    res.status(500).json({ success: false, message: 'server_error' });
  }
});

// === REFERIDOS: mis invitaciones (del emisor) ===
// Devuelve lista de invitaciones del usuario autenticado + cuántas le restan (máx. 6)
app.get('/api/invitaciones/mias', verificarToken, async (req, res) => {
  try {
    const emisor = req.usuario.username;

    const [cont, invs] = await Promise.all([
      pool.query('SELECT invitaciones_emitidas FROM invitaciones_contador WHERE usuario=$1', [emisor]),
      pool.query(`
        SELECT codigo, estado, receptor, creado_en, reclamado_en, activado_en
        FROM invitaciones
        WHERE emisor=$1
        ORDER BY creado_en DESC NULLS LAST, id DESC
      `, [emisor])
    ]);

    const emitidas = cont.rows[0]?.invitaciones_emitidas || 0;
    const restantes = Math.max(0, 6 - emitidas);

    const linkBase = process.env.PUBLIC_APP_URL || 'https://realtyinvestor.eu';
    const items = invs.rows.map(r => ({
      codigo: r.codigo,
      estado: r.estado,          // generado | reclamado | activado | rechazado
      receptor: r.receptor || null,
      creado_en: r.creado_en,
      reclamado_en: r.reclamado_en,
      activado_en: r.activado_en,
      link: `${linkBase}/entrar.html?ref=${encodeURIComponent(r.codigo)}`
    }));

    res.json({ success: true, restantes, emitidas, items });
  } catch (e) {
    console.error('GET /api/invitaciones/mias', e);
    res.status(500).json({ success: false, message: 'server_error' });
  }
});

// === REFERIDOS: generar código (usuario logueado) — NUEVA VERSIÓN CIFRADA ===
app.post('/api/invitaciones/generar', verificarToken, async (req, res) => {
  const client = await pool.connect();
  try {
    const emisor = req.usuario.username;

    const r0 = await client.query(
      'SELECT invitaciones_emitidas FROM invitaciones_contador WHERE usuario=$1',
      [emisor]
    );
    const emitidasIni = r0.rows[0]?.invitaciones_emitidas || 0;
    if (emitidasIni >= 6) {
      return res.status(400).json({ success: false, message: 'Máximo 6 invitaciones.' });
    }

    let codigo; let intentos = 0;
    while (true) {
      intentos++;
      codigo = buildReferralCodeFromUser(emisor); // ← usa el helper ya añadido
      try {
        await client.query('BEGIN');
        await client.query(
          'INSERT INTO invitaciones (codigo, emisor, meses_otorgables) VALUES ($1,$2,$3)',
          [codigo, emisor, 1]
        );
        if (r0.rows.length) {
          await client.query(
            'UPDATE invitaciones_contador SET invitaciones_emitidas = invitaciones_emitidas + 1 WHERE usuario=$1',
            [emisor]
          );
        } else {
          await client.query(
            'INSERT INTO invitaciones_contador (usuario, invitaciones_emitidas, meses_acumulados) VALUES ($1, 1, 0)',
            [emisor]
          );
        }
        await client.query('COMMIT');
        break;
      } catch (e) {
        await client.query('ROLLBACK');
        if (e && e.code === '23505' && intentos < 5) continue;
        console.error('generar invitación (código):', e);
        return res.status(500).json({ success: false, message: 'server_error' });
      }
    }

    // recálculo de emitidas/restantes tras la inserción
    const r1 = await pool.query(
      'SELECT invitaciones_emitidas FROM invitaciones_contador WHERE usuario=$1',
      [emisor]
    );
    const emitidas = r1.rows[0]?.invitaciones_emitidas || 0;
    const restantes = Math.max(0, 6 - emitidas);

    const linkBase = process.env.PUBLIC_APP_URL || 'https://realtyinvestor.eu';
    const link = `${linkBase}/entrar.html?ref=${encodeURIComponent(codigo)}`;

    res.json({ success: true, codigo, link, restantes, emitidas });
  } catch (e) {
    console.error('generar invitación', e);
    return res.status(500).json({ success: false, message: 'server_error' });
  } finally {
    client.release();
  }
});


// === PERFIL: consultar meses premium del usuario ===
app.get('/api/usuarios/:usuario/premium', verificarToken, async (req, res) => {
  try {
    const u = req.params.usuario;
    if (req.usuario.username !== u && req.usuario.username !== 'MVI') {
      return res.status(403).json({ success: false, message: 'Solo tu propio perfil' });
    }
    const r = await pool.query(
      'SELECT premium_months_active, premium_months_pending FROM usuarios WHERE usuario=$1',
      [u]
    );
    res.json({ success: true, ...r.rows[0] });
  } catch (e) {
    console.error('perfil premium', e);
    res.status(500).json({ success: false, message: 'server_error' });
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
    await pool.query(`
  INSERT INTO inversiones (usuario, propiedad, cantidad, divisa)
  VALUES ($1,$2,$3,$4)
  ON CONFLICT (usuario, propiedad)
  DO UPDATE SET
    cantidad = EXCLUDED.cantidad,
    divisa   = EXCLUDED.divisa,
    fecha    = now()
`, [usuario, propiedad, cantidad, divisa]);

    res.json({ success: true, message: 'Inversión registrada correctamente.' });
  } catch (e) {
    console.error(e);
    res.status(500).json({ success: false, message: 'Error al registrar inversión.' });
  }
});

// =========================
/* ADMIN dashboards */
// =========================
// DELETE — eliminar usuario por nombre (estrictamente solo MVI con JWT)
app.delete('/api/admin/usuarios/por-nombre/:usuario', verificarToken, async (req, res) => {
  try {
    if (req.usuario?.username !== 'MVI') {
      return res.status(403).json({ success: false, message: 'Acceso denegado.' });
    }

    const usuario = req.params.usuario;
    if (!usuario) return res.status(400).json({ success: false, message: 'Falta usuario.' });

    // Evitar borrarte a ti mismo o borrar la propia cuenta MVI (recomendado)
    if (usuario === 'MVI') {
      return res.status(400).json({ success: false, message: 'La cuenta no puede eliminarse.' });
    }

    const r = await pool.query('DELETE FROM usuarios WHERE usuario = $1 RETURNING usuario', [usuario]);

    if (!r.rowCount) {
      return res.status(404).json({ success: false, message: 'Usuario no encontrado.' });
    }

    res.json({ success: true, message: `Usuario ${usuario} eliminado.` });
  } catch (e) {
    console.error('DELETE /api/admin/usuarios/por-nombre/:usuario', e);
    res.status(500).json({ success: false, message: 'Error al eliminar usuario.' });
  }
});


// === RUTA PÚBLICA: contador de usuarios ===
app.get('/api/public/usercount', async (req, res) => {
  try {
    const result = await pool.query('SELECT COUNT(*) AS total FROM usuarios');
    res.json({ total: parseInt(result.rows[0].total, 10) });
  } catch (err) {
    console.error('Error al obtener conteo de usuarios:', err);
    res.status(500).json({ error: 'Error interno del servidor' });
  }
});



// Alias que te faltaba: /api/admin/data -> igual que /api/admin/datos
// Protege la lista de usuarios e inversiones solo para MVI
// Alias que te faltaba: /api/admin/data -> igual que /api/admin/datos
// Protege la lista de usuarios e inversiones solo para MVI
app.get('/api/admin/data', verificarToken, (req, res, next) => {
  if (req.usuario.username !== 'MVI') {
    return res.status(403).json({ success: false, message: 'Acceso denegado.' });
  }
  next();
}, async (req, res) => {
  try {
    // Añadimos id y tipo, y ordenamos por id DESC (más recientes primero)
    const usuarios = await pool.query(
      'SELECT id, usuario, email, tipo FROM usuarios ORDER BY id DESC'
    );
    const inversiones = await pool.query(
      'SELECT usuario, propiedad, cantidad, divisa, fecha FROM inversiones ORDER BY fecha DESC'
    );
    res.json({ success: true, usuarios: usuarios.rows, inversiones: inversiones.rows });
  } catch (e) {
    console.error('Error /api/admin/data:', e);
    res.status(500).json({ success: false, message: 'Error al obtener datos.' });
  }
});

// Ruta original (por compatibilidad con tu versión anterior)
app.get('/api/admin/datos', async (req, res) => {
  const admin = req.query.admin;
  if (admin !== 'MVI') return res.status(403).json({ success: false, message: 'Acceso denegado.' });
  try {
    const usuarios = await pool.query(
      'SELECT id, usuario, email, tipo FROM usuarios ORDER BY id DESC'
    );
    const inversiones = await pool.query(
      'SELECT usuario, propiedad, cantidad, divisa, fecha FROM inversiones ORDER BY fecha DESC'
    );
    res.json({ success: true, usuarios: usuarios.rows, inversiones: inversiones.rows });
  } catch (e) {
    console.error('Error /api/admin/datos:', e);
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

app.get('/api/activos', (req, res) => {
  const q = String(req.query.q || '').toLowerCase();
  const items = propiedades
    .filter(p => !q || p.id.toLowerCase().includes(q) || (p.nombre || '').toLowerCase().includes(q))
    .map(p => ({
      id: p.id,
      nombre: p.nombre || p.id,
      imagen: p.imagen,
      rentabilidad: p.rentabilidad,   // % anual
      plazo: p.plazo,                 // meses (asegúrate de tenerlo en el JSON)
      link: p.link
    }));
  res.json({ items });
});

// === Cartera de usuario ===

// GET — cartera completa con "join" a propiedades.json
app.get('/api/cartera/:usuario', async (req, res) => {
  const usuario = req.params.usuario;
  const viewer = req.header('X-Username') || null;
  try {
    const upub = await pool.query('SELECT cartera_publica FROM usuarios WHERE usuario=$1', [usuario]);
    const esPublica = !!upub.rows?.[0]?.cartera_publica;
    const esDueno = viewer === usuario;

    if (!esDueno && !esPublica) return res.json({ items: [] });

    const r = await pool.query(
      'SELECT propiedad, cantidad, divisa, fecha FROM inversiones WHERE usuario=$1 ORDER BY fecha DESC',
      [usuario]
    );
    const items = r.rows.map(row => {
      const info = propiedades.find(p => p.id === row.propiedad) || {};
      return {
        id: row.propiedad,
        cantidad: row.cantidad,
        divisa: row.divisa,
        fecha: row.fecha,
        codigo: row.propiedad,
        imagen: info.imagen || null,
        rentabilidad: info.rentabilidad ?? null,
        plazo: info.plazo ?? null,
        link: info.link || null,
        nombre: info.nombre || row.propiedad
      };
    });
    res.json({ items });
  } catch (e) {
    console.error('GET /api/cartera', e);
    res.status(500).json({ error: 'server_error' });
  }
});


// POST — upsert (crear o actualizar cantidad)
app.post('/api/cartera', async (req, res) => {
  const { usuario, propiedadId, cantidad, divisa } = req.body || {};
  if (!usuario || !propiedadId || !cantidad) {
    return res.status(400).json({ success: false, message: 'Faltan datos.' });
  }
  const _divisa = divisa || 'EUR';
  try {
    await pool.query(`
      INSERT INTO inversiones (usuario, propiedad, cantidad, divisa)
      VALUES ($1,$2,$3,$4)
      ON CONFLICT (usuario, propiedad)
      DO UPDATE SET cantidad = EXCLUDED.cantidad, divisa = EXCLUDED.divisa, fecha = now()
    `, [usuario, propiedadId, cantidad, _divisa]);
    res.json({ success: true });
  } catch (e) {
    console.error('POST /api/cartera', e);
    res.status(500).json({ success: false });
  }
});

// DELETE — quitar un activo de la cartera
app.delete('/api/cartera', async (req, res) => {
  const { usuario, propiedadId } = req.body || {};
  if (!usuario || !propiedadId) {
    return res.status(400).json({ success: false, message: 'Faltan datos.' });
  }
  try {
    await pool.query('DELETE FROM inversiones WHERE usuario=$1 AND propiedad=$2', [usuario, propiedadId]);
    res.json({ success: true });
  } catch (e) {
    console.error('DELETE /api/cartera', e);
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
//  (API) — robusto: ids como texto
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

// GET /me
communityRouter.get('/me', (req, res) => {
  if (!req._authedUser) return res.json(null);
  res.json({ id: req._authedUser.id, username: req._authedUser.usuario });
});

// GET /posts (ids como texto, cuenta likes/comentarios por subconsultas)
communityRouter.get('/posts', async (req, res) => {
  try {
    const me = req._authedUser;
    const offset = Math.max(parseInt(req.query.offset || '0', 10), 0);
    const limit = Math.min(Math.max(parseInt(req.query.limit || '10', 10), 1), 50);
    const q = (req.query.q || '').trim();
    const cats = (req.query.cats || '').split(',').filter(Boolean);
    const sort = (req.query.sort || 'recientes');

    const where = [];
    const params = [];
    let i = 1;

    if (cats.length) { where.push(`p.categoria = ANY($${i++}::text[])`); params.push(cats); }
    if (q) { where.push(`(p.titulo ILIKE $${i} OR (p.contenido->>'text') ILIKE $${i})`); params.push(`%${q}%`); i++; }
    const whereSql = where.length ? `WHERE ${where.join(' AND ')}` : '';

    const likedByMe = me
      ? `EXISTS (SELECT 1 FROM community_likes cl WHERE cl.post_id = p.id::text AND cl.user_id = $${i}) AS liked_by_me`
      : `false AS liked_by_me`;

    const likeCountSql = `(SELECT COUNT(*)::INT FROM community_likes cl WHERE cl.post_id = p.id::text) AS likes`;
    const commCountSql = `(SELECT COUNT(*)::INT FROM community_comments cc WHERE cc.post_id = p.id::text) AS comentarios`;

    let orderSql = 'ORDER BY p.created_at DESC';
    if (sort === 'likes') orderSql = 'ORDER BY likes DESC, p.created_at DESC';
    if (sort === 'comentarios') orderSql = 'ORDER BY comentarios DESC, p.created_at DESC';

    const listSql = `
      SELECT
        p.id,
        COALESCE(p.autor, u.usuario) AS autor,
        u.picture,
        u.public_google_avatar,
        p.categoria, p.titulo, p.contenido, p.tipo, p.created_at,
        ${likeCountSql}, ${commCountSql}, ${likedByMe}
      FROM community_posts p
      LEFT JOIN usuarios u ON u.id = p.user_id
      ${whereSql}
      ${orderSql}
      OFFSET $${me ? i + 1 : i} LIMIT $${me ? i + 2 : i + 1};
    `;


    const listParams = [...params];
    if (me) listParams.push(me.id);
    listParams.push(offset, limit);

    const countSql = `SELECT COUNT(*)::INT AS total FROM community_posts p ${whereSql};`;

    const [list, count] = await Promise.all([
      pool.query(listSql, listParams),
      pool.query(countSql, params)
    ]);

    // ...después de ejecutar listSql y countSql:
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
        created_at: r.created_at,
        avatar_url: (r.public_google_avatar && r.picture) ? r.picture : null
      };

      if (r.tipo === 'encuesta' || Array.isArray(r.contenido)) {
        return { ...base, opciones: Array.isArray(r.contenido) ? r.contenido : [], votos: [] };
      }

      const c = r.contenido || {};
      return { ...base, contenido: c.text || '', video: c.video || null };
    });

    res.json({ items, total: count.rows[0].total });

  } catch (e) {
    console.error('GET /api/community/posts', e);
    res.status(500).json({ error: 'server_error' });
  }
});

// GET /posts/:id  (id como texto)
communityRouter.get('/posts/:id', async (req, res) => {
  const id = String(req.params.id);
  const me = req._authedUser;
  try {
    const r = await pool.query(
      `SELECT p.id, p.user_id,
              COALESCE(p.autor, u.usuario) AS autor,
              u.picture,
              u.public_google_avatar,
              p.categoria, p.titulo, p.contenido, p.tipo, p.created_at
         FROM community_posts p
         LEFT JOIN usuarios u ON u.id = p.user_id
        WHERE p.id::text=$1
        LIMIT 1`, [id]
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
      id: p.id,
      autor: p.autor,
      categoria: p.categoria,
      titulo: p.titulo,
      contenido: p.contenido?.text || '',
      video: p.contenido?.video || null,
      tipo: 'post',
      created_at: p.created_at,
      likes,
      comentariosCount,
      likedByMe,
      avatar_url: (p.public_google_avatar && p.picture) ? p.picture : null
    });


  } catch (e) {
    console.error('GET /api/community/posts/:id', e);
    res.status(500).json({ error: 'server_error' });
  }
});

// GET /posts/:id/comments
// GET /posts/:id/comments
communityRouter.get('/posts/:id/comments', async (req, res) => {
  const id = String(req.params.id);
  try {
    const r = await pool.query(
      `SELECT c.id, c.contenido, c.created_at,
              u.usuario AS autor,
              u.picture,
              u.public_google_avatar
         FROM community_comments c
         JOIN usuarios u ON u.id = c.user_id
        WHERE c.post_id = $1
        ORDER BY c.created_at ASC`, [id]
    );

    const comments = r.rows.map(row => ({
      id: row.id,
      contenido: row.contenido,
      created_at: row.created_at,
      autor: row.autor,
      avatar_url: (row.public_google_avatar && row.picture) ? row.picture : null
    }));

    res.json(comments);
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

    const { categoria, titulo, contenido, tipo = 'post', video_url } = req.body;
    if (!titulo || (tipo === 'post' && !contenido)) {
      return res.status(400).json({ error: 'invalid_payload' });
    }

    const cat = sanitizeCategoria(categoria || 'Opinión');

    // extraer ID de YouTube si vino video_url
    let video = null;
    if (video_url) {
      const YT_ID =
        String(video_url).trim().match(/youtu\.be\/([A-Za-z0-9_-]{11})/)?.[1] ||
        String(video_url).trim().match(/[?&]v=([A-Za-z0-9_-]{11})/)?.[1] ||
        null;
      if (YT_ID) video = { provider: 'youtube', id: YT_ID, url: video_url };
    }

    let jsonContenido;
    if (tipo === 'encuesta') {
      jsonContenido = JSON.stringify(contenido);
    } else {
      jsonContenido = JSON.stringify({ text: String(contenido || ''), ...(video ? { video } : {}) });
    }

    const ins = await pool.query(
      `INSERT INTO community_posts (user_id, autor, categoria, titulo, contenido, tipo)
       VALUES ($1,$2,$3,$4,$5,$6)
       RETURNING id, autor, categoria, titulo, contenido, tipo, created_at`,
      [me.id, me.usuario, cat, titulo, jsonContenido, tipo]
    );
    const post = ins.rows[0];

    if (tipo === 'encuesta') {
      // ... (igual que ya tenías)
      return res.status(201).json({ /* opciones + votos… */ });
    }

    // ← Devuelve también el video para que se vea inmediatamente en el feed
    const c = post.contenido || {};
    const parsed = typeof c === 'object' ? c : JSON.parse(jsonContenido);
    return res.status(201).json({
      id: post.id,
      autor: post.autor,
      categoria: post.categoria,
      titulo: post.titulo,
      contenido: parsed.text || '',
      video: parsed.video || null,
      tipo: 'post',
      created_at: post.created_at
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

  const id = String(req.params.id); // puede ser "3" o un UUID

  const client = await pool.connect();
  try {
    await client.query('BEGIN');

    // Verifica que el post exista (id::text)
    const p = await client.query(
      `SELECT user_id, titulo FROM community_posts WHERE id::text = $1`,
      [id]
    );
    if (!p.rowCount) {
      await client.query('ROLLBACK');
      return res.status(404).json({ error: 'not_found' });
    }

    // Asegura que community_likes.post_id sea TEXT (y sin FK colgando).
    // Esto evita 22P02/42804 si alguien dejó la columna en uuid.
    await client.query(`
      DO $$
      DECLARE dtype text;
      BEGIN
        SELECT data_type INTO dtype
        FROM information_schema.columns
        WHERE table_name='community_likes' AND column_name='post_id';

        IF dtype IS DISTINCT FROM 'text' THEN
          -- suelta cualquier FK sobre post_id
          PERFORM 1 FROM pg_constraint c
            JOIN pg_class t ON t.oid=c.conrelid
            JOIN pg_attribute a ON a.attrelid=c.conrelid AND a.attnum = ANY(c.conkey)
           WHERE c.contype='f' AND t.relname='community_likes' AND a.attname='post_id';
          IF FOUND THEN
            EXECUTE (
              SELECT format('ALTER TABLE community_likes DROP CONSTRAINT %I', c.conname)
              FROM pg_constraint c
              JOIN pg_class t ON t.oid=c.conrelid
              JOIN pg_attribute a ON a.attrelid=c.conrelid AND a.attnum = ANY(c.conkey)
              WHERE c.contype='f' AND t.relname='community_likes' AND a.attname='post_id'
              LIMIT 1
            );
          END IF;

          -- cambia a TEXT
          EXECUTE 'ALTER TABLE community_likes ALTER COLUMN post_id TYPE text USING post_id::text';
        END IF;
      END$$;
    `);

    // Toggle
    const has = await client.query(
      `SELECT 1 FROM community_likes WHERE post_id = $1 AND user_id = $2`,
      [id, me.id]
    );

    let liked = false;
    if (has.rowCount) {
      await client.query(
        `DELETE FROM community_likes WHERE post_id = $1 AND user_id = $2`,
        [id, me.id]
      );
    } else {
      await client.query(
        `INSERT INTO community_likes (post_id, user_id) VALUES ($1, $2)`,
        [id, me.id]
      );
      liked = true;

      // Notifica al dueño del post (si no soy yo)
      const targetUserId = p.rows[0].user_id || null;
      if (targetUserId && targetUserId !== me.id) {
        await client.query(
          `INSERT INTO community_notifications (user_id, titulo, mensaje)
           VALUES ($1, $2, $3)`,
          [targetUserId, 'Nuevo “me gusta”', `${me.usuario} ha indicado "me gusta" en: ${p.rows[0].titulo}`]
        );
      }
    }

    const count = await client.query(
      `SELECT COUNT(*)::int AS likes FROM community_likes WHERE post_id = $1`,
      [id]
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
  const id = String(req.params.id);
  const { contenido } = req.body;
  if (!contenido || !String(contenido).trim()) {
    return res.status(400).json({ error: 'empty_comment' });
  }

  const client = await pool.connect();
  try {
    await client.query('BEGIN');

    const p = await client.query(`SELECT user_id, titulo FROM community_posts WHERE id::text=$1`, [id]);
    if (!p.rowCount) {
      await client.query('ROLLBACK');
      return res.status(404).json({ error: 'not_found' });
    }

    const ins = await client.query(
      `INSERT INTO community_comments (post_id, user_id, contenido)
       VALUES ($1,$2,$3) RETURNING id, created_at`,
      [id, me.id, contenido]
    );

    const targetUserId = p.rows?.[0]?.user_id || null;
    if (targetUserId && targetUserId !== me.id) {
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
  const id = String(req.params.id);
  const { option } = req.body;
  const optIdx = parseInt(option, 10);
  if (!Number.isInteger(optIdx) || optIdx < 0) {
    return res.status(400).json({ error: 'invalid_option' });
  }

  const client = await pool.connect();
  try {
    await client.query('BEGIN');

    const p = await client.query(`SELECT tipo FROM community_posts WHERE id::text=$1`, [id]);
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
// GET /notifications
communityRouter.get('/notifications', async (req, res) => {
  if (!req._authedUser) return res.json([]);
  try {
    const r = await pool.query(
      `SELECT id, titulo, mensaje, "read" AS read, created_at
         FROM community_notifications
        WHERE user_id = $1
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
      `UPDATE community_notifications
          SET "read" = TRUE
        WHERE user_id = $1
          AND "read" = FALSE`,
      [req._authedUser.id]
    );
    res.json({ ok: true });
  } catch (e) {
    console.error('POST /api/community/notifications/read', e);
    res.status(500).json({ error: 'server_error' });
  }
});

// DELETE /api/community/posts/:id  -> solo el autor (o admin MVI) puede borrar
communityRouter.delete('/posts/:id', async (req, res) => {
  const me = req._authedUser;
  if (!me) return res.status(401).json({ error: 'auth_required' });
  const id = String(req.params.id);

  const client = await pool.connect();
  try {
    await client.query('BEGIN');

    const owner = await client.query(`SELECT user_id FROM community_posts WHERE id::text=$1`, [id]);
    if (!owner.rowCount) {
      await client.query('ROLLBACK');
      return res.status(404).json({ error: 'not_found' });
    }

    const isAdmin = req.usuario && (req.usuario.username === 'MVI');
    if (owner.rows[0].user_id !== me.id && !isAdmin) {
      await client.query('ROLLBACK');
      return res.status(403).json({ error: 'forbidden' });
    }

    // Limpieza de tablas hijas (post_id es TEXT y sin FK)
    await client.query(`DELETE FROM community_likes       WHERE post_id=$1`, [id]);
    await client.query(`DELETE FROM community_comments    WHERE post_id=$1`, [id]);
    await client.query(`DELETE FROM community_poll_votes  WHERE post_id=$1`, [id]);
    await client.query(`DELETE FROM community_poll_options WHERE post_id=$1`, [id]);
    await client.query(`DELETE FROM community_posts       WHERE id::text=$1`, [id]);

    await client.query('COMMIT');
    res.json({ ok: true });
  } catch (e) {
    await client.query('ROLLBACK');
    console.error('DELETE /api/community/posts/:id', e);
    res.status(500).json({ error: 'server_error' });
  } finally {
    client.release();
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

// DELETE /api/my/opiniones/:id  -> solo el dueño de la opinión (o admin MVI)
app.delete('/api/my/opiniones/:id', async (req, res) => {
  const id = req.params.id;
  const headerUser = req.header('X-Username');
  if (!headerUser) return res.status(401).json({ error: 'auth_required' });

  try {
    const r = await pool.query(`SELECT usuario FROM comentarios WHERE id=$1`, [id]);
    if (!r.rows.length) return res.status(404).json({ error: 'not_found' });

    const isAdmin = req.usuario && (req.usuario.username === 'MVI');
    if (r.rows[0].usuario !== headerUser && !isAdmin) {
      return res.status(403).json({ error: 'forbidden' });
    }

    await pool.query(`DELETE FROM comentarios WHERE id=$1`, [id]);
    res.json({ ok: true });
  } catch (e) {
    console.error('DELETE /api/my/opiniones/:id', e);
    res.status(500).json({ error: 'server_error' });
  }
});

// PERFIL: solo el propio usuario
app.get('/api/perfil/:usuario', verificarToken, async (req, res) => {
  const usuario = req.params.usuario;
  try {
    if (req.usuario.username !== usuario && req.usuario.username !== 'MVI') {
      return res.status(403).json({ success: false, message: 'Acceso denegado.' });
    }

    const u = await pool.query(
      'SELECT usuario, email, descripcion, cartera_publica, picture, public_google_avatar FROM usuarios WHERE usuario = $1',
      [usuario]
    );
    if (!u.rows.length) return res.status(404).json({ success: false, message: 'Usuario no encontrado.' });

    const inv = await pool.query(
      'SELECT propiedad, cantidad, divisa, fecha FROM inversiones WHERE usuario = $1 ORDER BY fecha DESC',
      [usuario]
    );

    res.json({ success: true, user: u.rows[0], inversiones: inv.rows });
  } catch (e) {
    console.error('GET /api/perfil/:usuario', e);
    res.status(500).json({ success: false, message: 'Error al recuperar perfil.' });
  }
});

// === Actualizar datos básicos del perfil (usuario, descripción, email, avatar público)
app.post('/api/actualizar-perfil', verificarToken, async (req, res) => {
  const { original, nuevoUsuario, nuevaDescripcion, nuevoEmail, publicGoogleAvatar } = req.body || {};

  if (!original || !nuevoUsuario) {
    return res.status(400).json({ success: false, message: 'Faltan datos obligatorios.' });
  }

  // Solo puede cambiar su propio perfil o el admin MVI
  const loggedUser = req.usuario?.username;
  if (loggedUser !== original && loggedUser !== 'MVI') {
    return res.status(403).json({ success: false, message: 'No puedes editar este perfil.' });
  }

  const newUser = nuevoUsuario.trim();
  const newDesc = (nuevaDescripcion || '').trim();
  const newMail = (nuevoEmail || '').trim() || null;

  // Normalizamos la preferencia: si no viene, no tocamos la columna
  let publicAvatarValue = null;
  if (typeof publicGoogleAvatar === 'boolean') {
    publicAvatarValue = publicGoogleAvatar;
  }

  const client = await pool.connect();
  try {
    await client.query('BEGIN');

    // Comprobar que el usuario original existe
    const rUser = await client.query(
      'SELECT id, usuario FROM usuarios WHERE usuario = $1 LIMIT 1',
      [original]
    );
    if (!rUser.rows.length) {
      await client.query('ROLLBACK');
      return res.status(404).json({ success: false, message: 'Usuario original no encontrado.' });
    }

    // Si cambia el nombre, comprobar que no exista ya
    if (newUser !== original) {
      const rExists = await client.query(
        'SELECT 1 FROM usuarios WHERE usuario = $1 LIMIT 1',
        [newUser]
      );
      if (rExists.rows.length) {
        await client.query('ROLLBACK');
        return res.status(409).json({ success: false, message: 'Ese nombre de usuario ya está en uso.' });
      }
    }

    // Actualizar tabla principal de usuarios (incluyendo public_google_avatar si viene)
    await client.query(
      `
      UPDATE usuarios
         SET usuario = $1,
             email   = $2,
             descripcion = $3,
             public_google_avatar = COALESCE($4, public_google_avatar)
       WHERE usuario = $5
      `,
      [newUser, newMail, newDesc || null, publicAvatarValue, original]
    );

    // Si realmente ha cambiado el nombre, propagamos a las tablas que usan "usuario" como texto
    if (newUser !== original) {
      await client.query('UPDATE inversiones SET usuario = $1 WHERE usuario = $2', [newUser, original]);
      await client.query('UPDATE favoritos  SET usuario = $1 WHERE usuario = $2', [newUser, original]);
      await client.query('UPDATE comentarios SET usuario = $1 WHERE usuario = $2', [newUser, original]);
      await client.query('UPDATE invitaciones_contador SET usuario = $1 WHERE usuario = $2', [newUser, original]);
      await client.query('UPDATE invitaciones SET emisor = $1 WHERE emisor = $2', [newUser, original]);
      // Si en el futuro añades más tablas con campo "usuario", actualízalas aquí también
    }

    await client.query('COMMIT');
    return res.json({
      success: true,
      message: 'Perfil actualizado correctamente.',
      usuario: newUser
    });
  } catch (e) {
    await client.query('ROLLBACK');
    console.error('POST /api/actualizar-perfil', e);
    return res.status(500).json({ success: false, message: 'Error al actualizar el perfil.' });
  } finally {
    client.release();
  }
});

// === Exportar datos completos del perfil (para descarga JSON desde perfil.js)
app.get('/api/perfil/:usuario/export', verificarToken, async (req, res) => {
  const usuario = req.params.usuario;

  try {
    // Solo dueño o admin MVI
    if (req.usuario.username !== usuario && req.usuario.username !== 'MVI') {
      return res.status(403).json({ success: false, message: 'Acceso denegado.' });
    }

    const u = await pool.query(
      'SELECT id, usuario, email, descripcion, tipo, cartera_publica, premium_months_active, premium_months_pending, picture, public_google_avatar FROM usuarios WHERE usuario = $1',
      [usuario]
    );

    if (!u.rows.length) {
      return res.status(404).json({ success: false, message: 'Usuario no encontrado.' });
    }

    const inversiones = await pool.query(
      'SELECT propiedad, cantidad, divisa, fecha FROM inversiones WHERE usuario = $1 ORDER BY fecha DESC',
      [usuario]
    );

    const favoritos = await pool.query(
      'SELECT propiedad FROM favoritos WHERE usuario = $1',
      [usuario]
    );

    const comentarios = await pool.query(
      `SELECT id, propiedad, contenido, fecha, estado
         FROM comentarios
        WHERE usuario = $1
        ORDER BY fecha DESC`,
      [usuario]
    );

    // Último consentimiento (si existe)
    let consentimiento = null;
    try {
      const c = await pool.query(`
        SELECT c.*
          FROM consentimientos c
          JOIN usuarios u ON u.id = c.user_id
         WHERE u.usuario = $1
         ORDER BY c.fecha_consentimiento DESC
         LIMIT 1
      `, [usuario]);
      consentimiento = c.rows[0] || null;
    } catch (e) {
      // No rompemos la exportación si falla esto
      console.warn('No se pudo obtener consentimiento en export perfil:', e.message);
    }

    res.json({
      success: true,
      user: u.rows[0],
      inversiones: inversiones.rows,
      favoritos: favoritos.rows.map(r => r.propiedad),
      comentarios: comentarios.rows,
      consentimiento
    });
  } catch (e) {
    console.error('GET /api/perfil/:usuario/export', e);
    res.status(500).json({ success: false, message: 'Error al exportar datos.' });
  }
});


app.put('/api/perfil/cartera-privacidad', async (req, res) => {
  const viewer = req.header('X-Username');
  const { usuario, publica } = req.body || {};
  if (!viewer) return res.status(401).json({ success: false, message: 'Auth requerida' });
  if (!usuario || viewer !== usuario) return res.status(403).json({ success: false, message: 'Solo puedes editar tu perfil' });

  try {
    await pool.query('UPDATE usuarios SET cartera_publica = $1 WHERE usuario = $2', [!!publica, usuario]);
    res.json({ success: true });
  } catch (e) {
    console.error('PUT /api/perfil/cartera-privacidad', e);
    res.status(500).json({ success: false, message: 'No se pudo actualizar la privacidad' });
  }
});

// Guarda el token FCM que devuelve Firebase en el cliente
app.post('/api/push/register', async (req, res) => {
  try {
    // Acepta: JWT estándar (Authorization: Bearer ...) o cabecera X-Username (como ya haces en comunidad)
    let userRow = null;
    if (req.usuario?.id) {
      userRow = { id: req.usuario.id, usuario: req.usuario.username };
    } else {
      const headerUser = req.header('X-Username');
      if (headerUser) {
        const r = await pool.query(`SELECT id, usuario FROM usuarios WHERE usuario=$1 LIMIT 1`, [headerUser]);
        userRow = r.rows[0] || null;
      }
    }
    if (!userRow) return res.status(401).json({ success: false, message: 'auth_required' });

    const { token, platform } = req.body || {};
    if (!token) return res.status(400).json({ success: false, message: 'missing_token' });

    await pool.query(`
      INSERT INTO user_push_tokens (user_id, token, platform)
      VALUES ($1,$2,$3)
      ON CONFLICT (user_id, token)
      DO UPDATE SET last_seen=now(), platform=COALESCE(EXCLUDED.platform, user_push_tokens.platform)
    `, [userRow.id, token, platform || null]);

    res.json({ success: true });
  } catch (e) {
    console.error('POST /api/push/register', e);
    res.status(500).json({ success: false, message: 'server_error' });
  }
});

// Opcional: desregistrar token (cuando el usuario cierra sesión o el SW lo invalida)
app.post('/api/push/unregister', async (req, res) => {
  try {
    const headerUser = req.header('X-Username');
    const { token } = req.body || {};
    if (!headerUser || !token) return res.status(400).json({ success: false, message: 'missing_data' });
    await pool.query(`
      DELETE FROM user_push_tokens
      USING usuarios u
      WHERE user_push_tokens.user_id = u.id AND u.usuario=$1 AND user_push_tokens.token=$2
    `, [headerUser, token]);
    res.json({ success: true });
  } catch (e) {
    console.error('POST /api/push/unregister', e);
    res.status(500).json({ success: false });
  }
});
// Guarda en tu feed interno la notificación mostrada al usuario (ack desde el SW/cliente)
// Si incluye broadcastKey, la difunde a TODOS los usuarios con idempotencia.
app.post('/api/push/ingest', async (req, res) => {
  const client = await pool.connect();
  try {
    await client.query('BEGIN');

    // Resolver usuario (para el caso no-broadcast)
    let userId = null;
    if (req.usuario?.id) {
      userId = req.usuario.id;
    } else {
      const headerUser = req.header('X-Username');
      if (headerUser) {
        const r = await client.query(`SELECT id FROM usuarios WHERE usuario=$1 LIMIT 1`, [headerUser]);
        userId = r.rows[0]?.id || null;
      }
    }

    const { title, body, broadcastKey } = req.body || {};
    if (!title && !body) {
      await client.query('ROLLBACK');
      return res.status(400).json({ success: false, message: 'missing_payload' });
    }

    if (broadcastKey) {
      // Idempotencia: solo insertamos 1 vez por clave
      const insKey = await client.query(
        `INSERT INTO notif_broadcast (bkey) VALUES ($1)
         ON CONFLICT (bkey) DO NOTHING
         RETURNING bkey`,
        [broadcastKey]
      );

      if (insKey.rowCount > 0) {
        // Primera vez que vemos esta clave -> difundir a todos
        await client.query(
          `INSERT INTO community_notifications (user_id, titulo, mensaje)
           SELECT id, $1, $2 FROM usuarios`,
          [title || 'Notificación', body || '']
        );
      }
      await client.query('COMMIT');
      return res.json({ success: true, broadcast: true });
    }

    // Modo normal: guardar solo para el usuario que lo recibió
    if (!userId) {
      await client.query('ROLLBACK');
      return res.status(401).json({ success: false, message: 'auth_required' });
    }

    await client.query(
      `INSERT INTO community_notifications (user_id, titulo, mensaje) VALUES ($1,$2,$3)`,
      [userId, title || 'Notificación', body || '']
    );

    await client.query('COMMIT');
    res.json({ success: true, broadcast: false });
  } catch (e) {
    await client.query('ROLLBACK');
    console.error('POST /api/push/ingest', e);
    res.status(500).json({ success: false, message: 'server_error' });
  } finally {
    client.release();
  }
});

// =========================
// Start
// =========================
app.listen(PORT, () => {
  console.log(`✅ Servidor iniciado en http://localhost:${PORT}`);
});
