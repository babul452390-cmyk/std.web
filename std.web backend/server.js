require('dotenv').config();
const express    = require('express');
const { Pool }   = require('pg');
const bcrypt     = require('bcryptjs');
const jwt        = require('jsonwebtoken');
const cors       = require('cors');
const multer     = require('multer');
const cloudinary = require('cloudinary').v2;
const { CloudinaryStorage } = require('multer-storage-cloudinary');

const app          = express();
const PORT         = process.env.PORT || 5000;
const JWT_SECRET   = process.env.JWT_SECRET || 'student_admin_secret_2024';
const FRONTEND_URL = process.env.FRONTEND_URL || '*';
app.get('/', (req, res) => {
  res.send('Server is running successfully!');
});

// ── Cloudinary Config ─────────────────────────────────────────
cloudinary.config({
  cloud_name: process.env.CLOUDINARY_CLOUD_NAME,
  api_key:    process.env.CLOUDINARY_API_KEY,
  api_secret: process.env.CLOUDINARY_API_SECRET,
});

// ── PostgreSQL ────────────────────────────────────────────────
const db = new Pool({
  connectionString: process.env.DATABASE_URL,
  ssl: process.env.NODE_ENV === 'production' ? { rejectUnauthorized: false } : false,
});

// ── DB Init ───────────────────────────────────────────────────
async function initDB() {
  await db.query(`
    CREATE TABLE IF NOT EXISTS students (
      id              SERIAL PRIMARY KEY,
      name            TEXT    NOT NULL,
      email           TEXT    UNIQUE NOT NULL,
      phone           TEXT,
      dob             TEXT,
      gender          TEXT,
      class           TEXT,
      section         TEXT,
      roll_number     TEXT,
      address         TEXT,
      guardian_name   TEXT,
      guardian_phone  TEXT,
      photo           TEXT,
      created_at      TIMESTAMPTZ DEFAULT NOW()
    );

    CREATE TABLE IF NOT EXISTS admins (
      id         SERIAL PRIMARY KEY,
      username   TEXT UNIQUE NOT NULL,
      password   TEXT NOT NULL,
      created_at TIMESTAMPTZ DEFAULT NOW()
    );
  `);

  // Default admin
  const existing = await db.query('SELECT id FROM admins WHERE username = $1', ['admin']);
  if (existing.rowCount === 0) {
    await db.query(
      'INSERT INTO admins (username, password) VALUES ($1, $2)',
      ['admin', bcrypt.hashSync('admin123', 10)]
    );
    console.log('✅ Default admin created → username: admin  password: admin123');
  }

  console.log('✅ Database ready');
}

// ── Multer + Cloudinary Storage ───────────────────────────────
const storage = new CloudinaryStorage({
  cloudinary,
  params: {
    folder:         'student-photos',
    allowed_formats: ['jpg', 'jpeg', 'png', 'webp'],
    transformation: [{ width: 400, height: 400, crop: 'limit' }],
  },
});

const upload = multer({
  storage,
  limits: { fileSize: 2 * 1024 * 1024 },
  fileFilter: (_, file, cb) => {
    if (file.mimetype.startsWith('image/')) cb(null, true);
    else cb(new Error('Only images allowed'));
  },
});

// ── Middleware ────────────────────────────────────────────────
app.use(cors({
  origin:         FRONTEND_URL === '*' ? true : FRONTEND_URL.split(','),
  methods:        ['GET', 'POST', 'PUT', 'DELETE'],
  allowedHeaders: ['Content-Type', 'Authorization'],
}));
app.use(express.json());

// ── Auth Middleware ───────────────────────────────────────────
function auth(req, res, next) {
  const token = req.headers.authorization?.split(' ')[1];
  if (!token) return res.status(401).json({ error: 'Token required' });
  try { req.admin = jwt.verify(token, JWT_SECRET); next(); }
  catch { res.status(401).json({ error: 'Invalid or expired token' }); }
}

// ════════════════════════════════════════════════════════════
//  PUBLIC ROUTES
// ════════════════════════════════════════════════════════════

// Health check
app.get('/api/health', (_, res) =>
  res.json({ status: 'ok', time: new Date().toISOString() })
);

// Student Registration (with optional photo)
app.post('/api/register', upload.single('photo'), async (req, res) => {
  const { name, email, phone, dob, gender, class: cls,
          section, roll_number, address, guardian_name, guardian_phone } = req.body;

  if (!name || !email)
    return res.status(400).json({ error: 'Name and Email are required' });

  // Cloudinary returns the secure URL directly
  const photo = req.file ? req.file.path : null;

  try {
    const result = await db.query(`
      INSERT INTO students
        (name, email, phone, dob, gender, class, section, roll_number, address, guardian_name, guardian_phone, photo)
      VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12)
      RETURNING id
    `, [name, email, phone, dob, gender, cls, section, roll_number, address, guardian_name, guardian_phone, photo]);

    res.json({ success: true, message: 'Registration successful!', id: result.rows[0].id });
  } catch (err) {
    if (err.code === '23505') res.status(400).json({ error: 'Email already registered' });
    else res.status(500).json({ error: 'Server error: ' + err.message });
  }
});

// ════════════════════════════════════════════════════════════
//  ADMIN ROUTES
// ════════════════════════════════════════════════════════════

// Login
app.post('/api/admin/login', async (req, res) => {
  const { username, password } = req.body;
  const result = await db.query('SELECT * FROM admins WHERE username = $1', [username]);
  const admin  = result.rows[0];

  if (!admin || !bcrypt.compareSync(password, admin.password))
    return res.status(401).json({ error: 'Invalid credentials' });

  const token = jwt.sign(
    { id: admin.id, username: admin.username },
    JWT_SECRET,
    { expiresIn: '24h' }
  );
  res.json({ success: true, token, username: admin.username });
});

// Change admin password
app.put('/api/admin/change-password', auth, async (req, res) => {
  const { currentPassword, newPassword } = req.body;
  const result = await db.query('SELECT * FROM admins WHERE id = $1', [req.admin.id]);
  const admin  = result.rows[0];

  if (!bcrypt.compareSync(currentPassword, admin.password))
    return res.status(400).json({ error: 'Current password is wrong' });

  await db.query(
    'UPDATE admins SET password = $1 WHERE id = $2',
    [bcrypt.hashSync(newPassword, 10), req.admin.id]
  );
  res.json({ success: true, message: 'Password changed successfully' });
});

// Get all students (search + filter)
app.get('/api/admin/students', auth, async (req, res) => {
  const { search, class: cls, gender } = req.query;
  const params = [];
  let   idx    = 1;
  let   query  = 'SELECT * FROM students WHERE 1=1';

  if (search) {
    query += ` AND (name ILIKE $${idx} OR email ILIKE $${idx+1} OR roll_number ILIKE $${idx+2} OR phone ILIKE $${idx+3})`;
    params.push(...Array(4).fill(`%${search}%`));
    idx += 4;
  }
  if (cls)    { query += ` AND class = $${idx++}`;   params.push(cls); }
  if (gender) { query += ` AND gender = $${idx++}`;  params.push(gender); }
  query += ' ORDER BY created_at DESC';

  const result = await db.query(query, params);
  res.json(result.rows);
});

// Get single student
app.get('/api/admin/students/:id', auth, async (req, res) => {
  const result = await db.query('SELECT * FROM students WHERE id = $1', [req.params.id]);
  if (!result.rows[0]) return res.status(404).json({ error: 'Student not found' });
  res.json(result.rows[0]);
});

// Update student (with optional new photo)
app.put('/api/admin/students/:id', auth, upload.single('photo'), async (req, res) => {
  const { name, email, phone, dob, gender, class: cls,
          section, roll_number, address, guardian_name, guardian_phone } = req.body;

  const existing = await db.query('SELECT photo FROM students WHERE id = $1', [req.params.id]);
  const photo    = req.file ? req.file.path : (existing.rows[0]?.photo || null);

  // Delete old Cloudinary photo if a new one was uploaded
  if (req.file && existing.rows[0]?.photo) {
    try {
      const publicId = existing.rows[0].photo.split('/').slice(-2).join('/').split('.')[0];
      await cloudinary.uploader.destroy(publicId);
    } catch (_) { /* silently ignore delete errors */ }
  }

  try {
    await db.query(`
      UPDATE students
      SET name=$1, email=$2, phone=$3, dob=$4, gender=$5, class=$6,
          section=$7, roll_number=$8, address=$9, guardian_name=$10,
          guardian_phone=$11, photo=$12
      WHERE id=$13
    `, [name, email, phone, dob, gender, cls, section, roll_number, address, guardian_name, guardian_phone, photo, req.params.id]);

    res.json({ success: true, message: 'Updated successfully' });
  } catch (err) { res.status(500).json({ error: err.message }); }
});

// Delete student
app.delete('/api/admin/students/:id', auth, async (req, res) => {
  const result = await db.query('SELECT photo FROM students WHERE id = $1', [req.params.id]);
  const photo  = result.rows[0]?.photo;

  // Delete from Cloudinary
  if (photo) {
    try {
      const publicId = photo.split('/').slice(-2).join('/').split('.')[0];
      await cloudinary.uploader.destroy(publicId);
    } catch (_) { /* silently ignore */ }
  }

  await db.query('DELETE FROM students WHERE id = $1', [req.params.id]);
  res.json({ success: true });
});

// Dashboard stats
app.get('/api/admin/stats', auth, async (req, res) => {
  const [total, byClass, byGender, recent, monthly] = await Promise.all([
    db.query('SELECT COUNT(*) AS c FROM students'),
    db.query('SELECT class, COUNT(*) AS count FROM students GROUP BY class ORDER BY count DESC'),
    db.query('SELECT gender, COUNT(*) AS count FROM students GROUP BY gender'),
    db.query('SELECT * FROM students ORDER BY created_at DESC LIMIT 5'),
    db.query(`
      SELECT TO_CHAR(created_at, 'YYYY-MM') AS month, COUNT(*) AS count
      FROM students GROUP BY month ORDER BY month DESC LIMIT 6
    `),
  ]);

  res.json({
    total:    parseInt(total.rows[0].c),
    byClass:  byClass.rows,
    byGender: byGender.rows,
    recent:   recent.rows,
    monthly:  monthly.rows,
  });
});

// ── CSV Export ────────────────────────────────────────────────
app.get('/api/admin/export/csv', auth, async (req, res) => {
  const { rows } = await db.query('SELECT * FROM students ORDER BY id');
  const headers  = ['ID','Name','Email','Phone','Date of Birth','Gender','Class','Section','Roll Number','Address','Guardian Name','Guardian Phone','Registered At'];
  const csvRows  = rows.map(s => [
    s.id, `"${s.name}"`, s.email, s.phone||'', s.dob||'',
    s.gender||'', s.class||'', s.section||'', s.roll_number||'',
    `"${(s.address||'').replace(/"/g,'""')}"`,
    `"${s.guardian_name||''}"`, s.guardian_phone||'',
    s.created_at,
  ].join(','));

  res.setHeader('Content-Type', 'text/csv; charset=utf-8');
  res.setHeader('Content-Disposition', `attachment; filename="students_${Date.now()}.csv"`);
  res.send('\uFEFF' + [headers.join(','), ...csvRows].join('\n'));
});

// ── Start ─────────────────────────────────────────────────────
initDB()
  .then(() => {
    app.listen(PORT, () => {
      console.log(`\n🚀 Server → http://localhost:${PORT}`);
      console.log(`📦 PostgreSQL connected`);
      console.log(`🖼  Cloudinary storage active\n`);
    });
  })
  .catch(err => {
    console.error('❌ DB init failed:', err.message);
    process.exit(1);
  });
