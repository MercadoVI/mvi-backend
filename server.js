const express = require('express');
const cors = require('cors');
const path = require('path');
const bcrypt = require('bcrypt');
const Database = require('better-sqlite3');

// === Configuración ===
const app = express();
const db = new Database('usuarios.db');

// Middleware
app.use(cors());
app.use(express.json());
app.use(express.static(path.join(__dirname)));

// === Inicialización de tabla de usuarios ===
db.prepare(`
  CREATE TABLE IF NOT EXISTS inversiones (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    usuario TEXT,
    propiedad TEXT,
    cantidad REAL,
    divisa TEXT,
    fecha TEXT
  )
`).run();


// === Endpoint: Registro ===
app.post('/register', async (req, res) => {
  const { usuario, password, email } = req.body;

  if (!usuario || !password || !email) {
    return res.status(400).json({ success: false, message: 'Faltan campos obligatorios.' });
  }

  const existing = db.prepare('SELECT * FROM usuarios WHERE usuario = ?').get(usuario);
  if (existing) {
    return res.status(409).json({ success: false, message: 'El usuario ya existe.' });
  }

  const hashedPassword = await bcrypt.hash(password, 10);
  try {
    db.prepare('INSERT INTO usuarios (usuario, password, email, tipo) VALUES (?, ?, ?, ?)').run(usuario, hashedPassword, email, 'Inversor');
    res.json({ success: true, message: 'Usuario registrado con éxito.' });
  } catch (err) {
    res.status(500).json({ success: false, message: 'Error al registrar el usuario.' });
  }
});

// === Endpoint: Login ===
app.post('/login', async (req, res) => {
  const { usuario, password } = req.body;

  const user = db.prepare('SELECT * FROM usuarios WHERE usuario = ?').get(usuario);
  if (!user) {
    return res.status(401).json({ success: false, message: 'Usuario o contraseña incorrectos.' });
  }

  const valid = await bcrypt.compare(password, user.password);
  if (!valid) {
    return res.status(401).json({ success: false, message: 'Usuario o contraseña incorrectos.' });
  }

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
});

app.post('/api/inversion', (req, res) => {
  const { usuario, propiedad, cantidad, divisa } = req.body;

  if (!usuario || !propiedad || !cantidad || !divisa) {
    return res.status(400).json({ success: false, message: "Faltan datos obligatorios." });
  }

  const insert = db.prepare(`INSERT INTO inversiones (usuario, propiedad, cantidad, divisa, fecha) VALUES (?, ?, ?, ?, datetime('now'))`);
  insert.run(usuario, propiedad, cantidad, divisa);

  res.json({ success: true, message: "Inversión registrada correctamente." });
});

app.get('/api/perfil/:usuario', (req, res) => {
  const usuario = req.params.usuario;

  const user = db.prepare('SELECT usuario, email FROM usuarios WHERE usuario = ?').get(usuario);
  if (!user) return res.status(404).json({ success: false, message: 'Usuario no encontrado.' });

  const inversiones = db.prepare('SELECT propiedad, cantidad, divisa, fecha FROM inversiones WHERE usuario = ? ORDER BY fecha DESC').all(usuario);
  res.json({ success: true, user, inversiones });
});

app.get('/api/admin/datos', (req, res) => {
  const admin = req.query.admin;
  if (admin !== 'MVI') {
    return res.status(403).json({ success: false, message: "Acceso denegado." });
  }

  const usuarios = db.prepare('SELECT usuario, email FROM usuarios').all();
  const inversiones = db.prepare('SELECT usuario, propiedad, cantidad, divisa, fecha FROM inversiones ORDER BY fecha DESC').all();

  res.json({ success: true, usuarios, inversiones });
});

app.delete('/api/admin/eliminar', (req, res) => {
  const usuario = req.query.usuario;
  if (!usuario || usuario === "MVI") return res.status(400).json({ message: "No permitido." });

  db.prepare('DELETE FROM inversiones WHERE usuario = ?').run(usuario);
  db.prepare('DELETE FROM usuarios WHERE usuario = ?').run(usuario);
  res.json({ message: `Usuario "${usuario}" y sus inversiones han sido eliminadas.` });
});

// Endpoint: /api/admin/data — solo accesible para usuario 'MVI'
app.get('/api/admin/data', (req, res) => {
  try {
    const usuarios = db.prepare('SELECT usuario, email FROM usuarios').all();
    const inversiones = db.prepare('SELECT * FROM inversiones').all();

    res.json({ usuarios, inversiones });
  } catch (error) {
    console.error("Error al obtener datos administrativos:", error);
    res.status(500).json({ message: "Error interno del servidor" });
  }
});


// === Servir frontend ===
app.get('/', (req, res) => {
  res.sendFile(path.join(__dirname, 'index.html'));
});

// === Iniciar servidor ===
const PORT = 3000;
app.listen(PORT, () => {
  console.log(`✅ Servidor iniciado en http://localhost:${PORT}`);
});
