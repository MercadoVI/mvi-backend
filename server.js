const express = require('express');
const cors = require('cors');
const path = require('path');
const bcrypt = require('bcrypt');
const { Pool } = require('pg');

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
app.use(express.static(path.join(__dirname)));

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
    console.log("✅ Tablas verificadas.");
  } catch (err) {
    console.error("❌ Error al crear tablas:", err);
  }
})();

// === Registro de usuario ===
app.post('/register', async (req, res) => {
  const { usuario, password, email } = req.body;
  if (!usuario || !password || !email)
    return res.status(400).json({ success: false, message: 'Faltan campos obligatorios.' });

  try {
    const existing = await pool.query('SELECT * FROM usuarios WHERE usuario = $1', [usuario]);
    if (existing.rows.length > 0)
      return res.status(409).json({ success: false, message: 'El usuario ya existe.' });

    const hashedPassword = await bcrypt.hash(password, 10);
    await pool.query(
      'INSERT INTO usuarios (usuario, password, email, tipo) VALUES ($1, $2, $3, $4)',
      [usuario, hashedPassword, email, 'Inversor']
    );
    res.json({ success: true, message: 'Usuario registrado con éxito.' });
  } catch (err) {
    console.error(err);
    res.status(500).json({ success: false, message: 'Error al registrar el usuario.' });
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

    res.json({
      success: true,
      message: 'Inicio de sesión correcto.',
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
app.delete('/api/admin/eliminar', async (req, res) => {
  const usuario = req.query.usuario;
  if (!usuario || usuario === "MVI") return res.status(400).json({ message: "No permitido." });

  try {
    await pool.query('DELETE FROM inversiones WHERE usuario = $1', [usuario]);
    await pool.query('DELETE FROM usuarios WHERE usuario = $1', [usuario]);
    res.json({ message: `Usuario "${usuario}" y sus inversiones han sido eliminadas.` });
  } catch (err) {
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
  res.sendFile(path.join(__dirname, 'index.html'));
});

// === Iniciar servidor ===
app.listen(PORT, () => {
  console.log(`✅ Servidor iniciado en http://localhost:${PORT}`);
});
