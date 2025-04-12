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
  CREATE TABLE IF NOT EXISTS usuarios (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    usuario TEXT UNIQUE,
    password TEXT,
    email TEXT,
    tipo TEXT DEFAULT 'Inversor'
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

// === Servir frontend ===
app.get('/', (req, res) => {
  res.sendFile(path.join(__dirname, 'index.html'));
});

// === Iniciar servidor ===
const PORT = 3000;
app.listen(PORT, () => {
  console.log(`✅ Servidor iniciado en http://localhost:${PORT}`);
});
