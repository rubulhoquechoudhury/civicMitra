const path = require('path');
const fs = require('fs');
const express = require('express');
const expressLayouts = require('express-ejs-layouts');
const session = require('express-session');
const bcrypt = require('bcryptjs');
const multer = require('multer');
const sqlite3 = require('sqlite3').verbose();

const app = express();
const PORT = process.env.PORT || 3000;

const dbPath = path.join(__dirname, 'database.sqlite');
const db = new sqlite3.Database(dbPath);

const uploadsDir = path.join(__dirname, 'uploads');
if (!fs.existsSync(uploadsDir)) {
  fs.mkdirSync(uploadsDir);
}

const storage = multer.diskStorage({
  destination: (req, file, cb) => {
    cb(null, uploadsDir);
  },
  filename: (req, file, cb) => {
    const uniqueSuffix = Date.now() + '-' + Math.round(Math.random() * 1e9);
    const ext = path.extname(file.originalname) || '.jpg';
    cb(null, `${uniqueSuffix}${ext}`);
  },
});

const upload = multer({ storage });

app.set('view engine', 'ejs');
app.set('views', path.join(__dirname, 'views'));
app.set('layout', 'layout');

app.use(expressLayouts);
app.use(express.urlencoded({ extended: true }));
app.use(express.static(path.join(__dirname, 'public')));
app.use('/uploads', express.static(uploadsDir));

app.use(
  session({
    secret: 'civic-sense-secret',
    resave: false,
    saveUninitialized: false,
  })
);

function initDb() {
  db.serialize(() => {
    db.run(
      `CREATE TABLE IF NOT EXISTS users (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        email TEXT UNIQUE NOT NULL,
        password_hash TEXT NOT NULL,
        role TEXT NOT NULL CHECK(role IN ('citizen', 'authority')),
        authority_code TEXT,
        authority_state TEXT,
        authority_district TEXT
      )`
    );

    db.all("PRAGMA table_info(users)", (err, cols) => {
      if (!err && cols) {
        const hasState = cols.some((c) => c.name === 'authority_state');
        const hasDistrict = cols.some((c) => c.name === 'authority_district');
        if (!hasState) db.run('ALTER TABLE users ADD COLUMN authority_state TEXT');
        if (!hasDistrict) db.run('ALTER TABLE users ADD COLUMN authority_district TEXT');
      }
    });

    db.run(
      `CREATE TABLE IF NOT EXISTS reports (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        reporter_id INTEGER,
        state TEXT NOT NULL,
        district TEXT NOT NULL,
        post_office TEXT NOT NULL,
        pincode TEXT NOT NULL,
        civic_type TEXT NOT NULL,
        description TEXT,
        image_path TEXT,
        status TEXT NOT NULL CHECK(status IN ('unsolved', 'pending', 'resolved')) DEFAULT 'unsolved',
        created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
        updated_at DATETIME DEFAULT CURRENT_TIMESTAMP,
        FOREIGN KEY (reporter_id) REFERENCES users(id)
      )`
    );
  });
}

initDb();

function requireAuth(role) {
  return (req, res, next) => {
    if (!req.session.user) {
      return res.redirect('/login');
    }
    if (role && req.session.user.role !== role) {
      return res.status(403).send('Forbidden');
    }
    next();
  };
}

const ADMIN_USERNAME = 'admin';
const ADMIN_PASSWORD = 'admin';

function requireAdmin(req, res, next) {
  if (!req.session.admin) {
    return res.redirect('/admin');
  }
  next();
}

app.get('/', (req, res) => {
  res.render('index', { user: req.session.user });
});

app.get('/signup', (req, res) => {
  res.render('signup', { error: null });
});

app.post('/signup', async (req, res) => {
  const { email, password, role, authority_code, authority_state, authority_district } = req.body;
  if (!email || !password || !role) {
    return res.render('signup', { error: 'Please fill all required fields.' });
  }

  if (role === 'authority') {
    if (!authority_code) {
      return res.render('signup', { error: 'Authority code is required for authority signup.' });
    }
    if (!authority_state || !authority_district) {
      return res.render('signup', { error: 'Please select your state and district.' });
    }
  }

  try {
    const passwordHash = await bcrypt.hash(password, 10);
    const stmt = db.prepare(
      'INSERT INTO users (email, password_hash, role, authority_code, authority_state, authority_district) VALUES (?, ?, ?, ?, ?, ?)'
    );
    stmt.run(
      email,
      passwordHash,
      role,
      role === 'authority' ? authority_code : null,
      role === 'authority' ? authority_state : null,
      role === 'authority' ? authority_district : null,
      (err) => {
        if (err) {
          let message = 'Could not create account.';
          if (err.message && err.message.includes('UNIQUE')) {
            message = 'Email already registered.';
          }
          return res.render('signup', { error: message });
        }
        return res.redirect('/login');
      }
    );
  } catch (e) {
    return res.render('signup', { error: 'Unexpected error. Please try again.' });
  }
});

app.get('/login', (req, res) => {
  res.render('login', { error: null });
});

app.post('/login', (req, res) => {
  const { email, password, role, authority_code } = req.body;
  if (!email || !password || !role) {
    return res.render('login', { error: 'Please fill all required fields.' });
  }

  const query =
    role === 'authority'
      ? 'SELECT * FROM users WHERE email = ? AND role = ? AND authority_code = ?'
      : 'SELECT * FROM users WHERE email = ? AND role = ?';
  const params =
    role === 'authority' ? [email, role, authority_code || null] : [email, role];

  db.get(query, params, async (err, user) => {
    if (err || !user) {
      return res.render('login', { error: 'Invalid credentials.' });
    }

    const match = await bcrypt.compare(password, user.password_hash);
    if (!match) {
      return res.render('login', { error: 'Invalid credentials.' });
    }

    req.session.user = {
      id: user.id,
      email: user.email,
      role: user.role,
      authority_state: user.authority_state || null,
      authority_district: user.authority_district || null,
    };

    if (user.role === 'authority') {
      return res.redirect('/authority/dashboard');
    }
    return res.redirect('/citizen/dashboard');
  });
});

app.post('/logout', (req, res) => {
  req.session.destroy(() => {
    res.redirect('/');
  });
});

app.get('/citizen/dashboard', requireAuth('citizen'), (req, res) => {
  db.all(
    'SELECT * FROM reports WHERE reporter_id = ? ORDER BY created_at DESC',
    [req.session.user.id],
    (err, rows) => {
      const reports = rows || [];
      res.render('citizen_dashboard', { user: req.session.user, reports });
    }
  );
});

app.get('/report/new', requireAuth('citizen'), (req, res) => {
  const civicTypes = ['Garbage', 'Road Damage', 'Water Logging', 'Street Light', 'Other'];
  res.render('new_report', { user: req.session.user, civicTypes, error: null });
});

app.post(
  '/report/new',
  requireAuth('citizen'),
  upload.single('image'),
  (req, res) => {
    const {
      state,
      district,
      post_office,
      pincode,
      civic_type,
      description,
    } = req.body;

    if (!state || !district || !post_office || !pincode || !civic_type) {
      const civicTypes = ['Garbage', 'Road Damage', 'Water Logging', 'Street Light', 'Other'];
      return res.render('new_report', {
        user: req.session.user,
        civicTypes,
        error: 'Please fill all required fields.',
      });
    }

    const imagePath = req.file ? `/uploads/${req.file.filename}` : null;

    const stmt = db.prepare(
      `INSERT INTO reports
      (reporter_id, state, district, post_office, pincode, civic_type, description, image_path, status)
      VALUES (?, ?, ?, ?, ?, ?, ?, ?, 'unsolved')`
    );

    stmt.run(
      req.session.user.id,
      state,
      district,
      post_office,
      pincode,
      civic_type,
      description || '',
      imagePath,
      (err) => {
        if (err) {
          const civicTypes = ['Garbage', 'Road Damage', 'Water Logging', 'Street Light', 'Other'];
          return res.render('new_report', {
            user: req.session.user,
            civicTypes,
            error: 'Could not save report. Please try again.',
          });
        }
        return res.redirect('/citizen/dashboard');
      }
    );
  }
);

app.get('/authority/dashboard', requireAuth('authority'), (req, res) => {
  const { authority_state, authority_district } = req.session.user;
  let query =
    'SELECT id, state, district, post_office, pincode, civic_type, description, image_path, status, created_at, updated_at FROM reports';
  const params = [];
  if (authority_state && authority_district) {
    query += ' WHERE state = ? AND district = ?';
    params.push(authority_state, authority_district);
  }
  query += ' ORDER BY created_at DESC';

  db.all(query, params, (err, rows) => {
    const reports = rows || [];
    res.render('authority_dashboard', { user: req.session.user, reports });
  });
});

app.post('/authority/report/:id/status', requireAuth('authority'), (req, res) => {
  const { id } = req.params;
  const { status } = req.body;
  const { authority_state, authority_district } = req.session.user;
  const allowed = ['unsolved', 'pending', 'resolved'];
  if (!allowed.includes(status)) {
    return res.redirect('/authority/dashboard');
  }

  const updateReport = () => {
    const stmt = db.prepare(
      'UPDATE reports SET status = ?, updated_at = CURRENT_TIMESTAMP WHERE id = ?'
    );
    stmt.run(status, id, () => res.redirect('/authority/dashboard'));
  };

  if (!authority_state || !authority_district) {
    updateReport();
    return;
  }

  db.get(
    'SELECT id FROM reports WHERE id = ? AND state = ? AND district = ?',
    [id, authority_state, authority_district],
    (err, row) => {
      if (err || !row) {
        return res.redirect('/authority/dashboard');
      }
      updateReport();
    }
  );
});

// Super Admin routes
app.get('/admin', (req, res) => {
  if (req.session.admin) {
    return res.redirect('/admin/dashboard');
  }
  res.render('admin_login', { error: null, layout: false });
});

app.post('/admin/login', (req, res) => {
  const { username, password } = req.body;
  if (username === ADMIN_USERNAME && password === ADMIN_PASSWORD) {
    req.session.admin = true;
    return res.redirect('/admin/dashboard');
  }
  res.render('admin_login', { error: 'Invalid admin credentials.', layout: false });
});

app.post('/admin/logout', (req, res) => {
  req.session.admin = false;
  res.redirect('/admin');
});

app.get('/admin/dashboard', requireAdmin, (req, res) => {
  db.all('SELECT id, email, role, authority_code, authority_state, authority_district FROM users ORDER BY id', [], (errUsers, users) => {
    if (errUsers) {
      return res.redirect('/admin/dashboard');
    }
    db.all(
      'SELECT id, reporter_id, state, district, post_office, pincode, civic_type, description, image_path, status, created_at FROM reports ORDER BY created_at DESC',
      [],
      (errReports, reports) => {
        if (errReports) {
          return res.redirect('/admin/dashboard');
        }
        res.render('admin_dashboard', {
          users: users || [],
          reports: reports || [],
          layout: 'admin_layout',
        });
      }
    );
  });
});

app.post('/admin/delete-user/:id', requireAdmin, (req, res) => {
  const userId = req.params.id;
  db.run('DELETE FROM reports WHERE reporter_id = ?', [userId], (err) => {
    if (err) {
      return res.redirect('/admin/dashboard');
    }
    db.run('DELETE FROM users WHERE id = ?', [userId], (err2) => {
      res.redirect('/admin/dashboard');
    });
  });
});

app.post('/admin/delete-report/:id', requireAdmin, (req, res) => {
  const reportId = req.params.id;
  db.get('SELECT image_path FROM reports WHERE id = ?', [reportId], (err, row) => {
    if (err || !row) {
      return res.redirect('/admin/dashboard');
    }
    if (row.image_path) {
      const filePath = path.join(__dirname, row.image_path.replace(/^\//, ''));
      if (fs.existsSync(filePath)) {
        fs.unlinkSync(filePath);
      }
    }
    db.run('DELETE FROM reports WHERE id = ?', [reportId], () => {
      res.redirect('/admin/dashboard');
    });
  });
});

app.listen(PORT, () => {
  console.log(`Civic Mitra running on http://localhost:${PORT}`);
});

