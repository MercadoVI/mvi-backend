const express = require('express');
const cors = require('cors');
const path = require('path');
const bcrypt = require('bcrypt');
const { Pool } = require('pg');
const propiedades = require('./propiedades.json');

const app = express();
const PORT = process.env.PORT || 3000;

// === Configuración de conexión a PostgreSQL ===
const pool = new Pool({
  connectionString: process.env.DATABASE_URL,
  ssl: { rejectUnauthorized: false } // necesario en Render
});

// === Middleware ===
app.use(cors());
app.use(express.json());

// === Crear tablas si no existen ===
(async () => {
  try {
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
      CREATE TABLE consentimientos (
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

    console.log("✅ Tablas verificadas.");
  } catch (err) {
    console.error("❌ Error al crear tablas:", err);
  }
})();

function verificarAdminMVI(req, res, next) {
  const usuario = req.usuario; // Este debe estar ya seteado por el middleware de autenticación

  if (usuario && usuario.username === "MVI") {
    next();
  } else {
    res.status(403).json({ error: "Acceso denegado. Solo para el administrador MVI." });
  }
}

const jwt = require("jsonwebtoken");

function verificarToken(req, res, next) {
  const authHeader = req.headers.authorization;
  const token = authHeader?.split(" ")[1];

  if (!token) {
    return res.status(401).json({ error: "Token no proporcionado" });
  }

  jwt.verify(token, "CLAVE_SECRETA", (err, decoded) => {
    if (err) return res.status(403).json({ error: "Token inválido" });

    req.usuario = decoded; // contiene username y cualquier dato que codifiques
    next();
  });
}


app.get("/admin/consentimientos", verificarToken, verificarAdminMVI, async (req, res) => {
  try {
    const result = await pool.query(`
      SELECT u.usuario, u.email, c.fecha_consentimiento, c.version_politica, c.ip_usuario
      FROM consentimientos c
      JOIN usuarios u ON u.id = c.user_id
      ORDER BY c.fecha_consentimiento DESC
    `);

    res.json(result.rows);
  } catch (err) {
    console.error("Error al consultar consentimientos:", err);
    res.status(500).json({ error: "Error interno del servidor" });
  }
});




// === Registro de usuario ===
app.post("/register", async (req, res) => {
  const { usuario, email, password, acepta_privacidad, acepta_terminos } = req.body;
  const ip = req.ip;

  if (!acepta_privacidad || !acepta_terminos) {
    return res.status(400).json({ error: "Debes aceptar las políticas legales." });
  }

  const client = await pool.connect();
  const hashedPassword = await bcrypt.hash(password, 10);

  try {
    await client.query("BEGIN");

    // 1. Crear usuario
    const result = await client.query(
      `INSERT INTO usuarios (usuario, email, password)
       VALUES ($1, $2, $3)
       RETURNING id`,
      [usuario, email, hashedPassword]
    );

    const userId = result.rows[0].id;

    // 2. Registrar consentimiento
    await client.query(
      `INSERT INTO consentimientos (
        user_id, acepta_privacidad, acepta_terminos, ip_usuario
      ) VALUES ($1, $2, $3, $4)`,
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


// === Login de usuario ===
app.post('/login', async (req, res) => {
  const { usuario, password } = req.body;
  try {
    const result = await pool.query('SELECT * FROM usuarios WHERE usuario = $1', [usuario]);
    const user = result.rows[0];

    if (!user) return res.status(401).json({ success: false, message: 'Usuario o contraseña incorrectos.' });

    const valid = await bcrypt.compare(password, user.password);
    if (!valid) return res.status(401).json({ success: false, message: 'Usuario o contraseña incorrectos.' });

    // Crear token JWT
    const token = jwt.sign(
      { id: user.id, username: user.usuario, tipo: user.tipo },
      'CLAVE_SECRETA',
      { expiresIn: '2h' }
    );

    res.json({
      success: true,
      message: 'Inicio de sesión correcto.',
      token,
      user: {
        id: user.id,
        usuario: user.usuario,
        email: user.email,
        tipo: user.tipo
      }
    });
  } catch (err) {
    res.status(500).json({ success: false, message: 'Error al iniciar sesión.' });
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

// === Perfil de usuario (datos e inversiones) ===
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

// === Eliminar usuario (solo admin) ===
// ✅ Nueva ruta para eliminar usuario por nombre (usuario)
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

// === Servir frontend ===
app.get('/', (req, res) => {
  res.send("Backend MVI activo");
});



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

// Historial de comentarios por usuario (solo aprobados)
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

app.post("/api/actualizar-perfil", async (req, res) => {
  const { original, nuevoUsuario, nuevaDescripcion } = req.body;
  if (!original || !nuevoUsuario) return res.status(400).json({ success: false, message: "Faltan datos" });

  try {
    const stmt = db.prepare("UPDATE usuarios SET usuario = ?, descripcion = ? WHERE usuario = ?");
    const result = stmt.run(nuevoUsuario, nuevaDescripcion, original);
    if (result.changes > 0) {
      res.json({ success: true });
    } else {
      res.json({ success: false, message: "No se actualizó ningún perfil." });
    }
  } catch (err) {
    res.status(500).json({ success: false, message: "Error en la base de datos", error: err.message });
  }
});


// === Añadir favorito ===
app.post('/api/favoritos', async (req, res) => {
  const { usuario, propiedadId } = req.body;
  if (!usuario || !propiedadId)
    return res.status(400).json({ success: false, message: "Faltan datos." });

  try {
    const existe = await pool.query(
      'SELECT * FROM favoritos WHERE usuario = $1 AND propiedad = $2',
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

// === Eliminar favorito ===
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

// === Obtener favoritos de un usuario ===
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

app.get('/api/propiedades/:id', (req, res) => {
  const prop = propiedades.find(p => p.id === req.params.id);
  if (!prop) return res.status(404).json({ success: false });
  res.json(prop);
});



// === Iniciar servidor ===
app.listen(PORT, () => {
  console.log(`✅ Servidor iniciado en http://localhost:${PORT}`);
});
