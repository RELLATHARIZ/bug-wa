const express = require('express');
const session = require('express-session');
const SQLiteStore = require('better-sqlite3');
const bcrypt = require('bcryptjs');
const helmet = require('helmet');
const rateLimit = require('express-rate-limit');
const path = require('path');

const app = express();
const db = new SQLiteStore(path.join(__dirname, 'nightmare.db'));
db.exec(`CREATE TABLE IF NOT EXISTS users (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  username TEXT UNIQUE NOT NULL,
  password_hash TEXT NOT NULL,
  role TEXT NOT NULL CHECK(role IN ('Owner','Developer','Admin','VIP','Member')),
  created_at TEXT DEFAULT CURRENT_TIMESTAMP
)`);

// Bootstrap the first Owner only when environment variables are set and no Owner exists.
if (!db.prepare("SELECT id FROM users WHERE role='Owner' LIMIT 1").get()) {
  const username = process.env.NIGHTMARE_OWNER_USERNAME;
  const password = process.env.NIGHTMARE_OWNER_PASSWORD;
  if (username && password && password.length >= 12) {
    db.prepare('INSERT INTO users (username,password_hash,role) VALUES (?,?,?)')
      .run(username, bcrypt.hashSync(password, 12), 'Owner');
    console.log('Initial Owner account created from environment settings.');
  } else {
    console.warn('No Owner yet. Set NIGHTMARE_OWNER_USERNAME and NIGHTMARE_OWNER_PASSWORD (12+ chars) before first startup.');
  }
}


app.use(helmet({ contentSecurityPolicy: { directives: { defaultSrc: ["'self'"], scriptSrc: ["'self'"], styleSrc: ["'self'"], imgSrc: ["'self'", 'data:'] }}}));
app.use(express.json({limit:'8kb'}));
app.use(session({
  secret: process.env.NIGHTMARE_SESSION_SECRET || (() => { throw new Error('Set NIGHTMARE_SESSION_SECRET to a long random secret'); })(),
  resave: false, saveUninitialized: false,
  cookie: { httpOnly: true, sameSite: 'strict', secure: process.env.NODE_ENV === 'production', maxAge: 1000*60*60*4 }
}));
app.use('/api/login', rateLimit({windowMs: 15*60*1000, limit: 8, standardHeaders: true, legacyHeaders: false}));
app.use(express.static(path.join(__dirname, 'public')));

const getUser = (username) => db.prepare('SELECT * FROM users WHERE username=?').get(username);
const auth = (req,res,next) => req.session.user ? next() : res.status(401).json({error:'Login required'});
const rolesCanCreate = ['Owner','Developer'];
const roleOrder = ['Owner','Developer','Admin','VIP','Member'];
function canCreateRole(actor, target) {
  if (actor.role === 'Owner') return ['Developer','Admin','VIP','Member'].includes(target);
  if (actor.role === 'Developer') return ['Admin','VIP','Member'].includes(target);
  return false;
}

app.post('/api/login', (req,res) => {
  const {username,password} = req.body || {};
  if (typeof username !== 'string' || typeof password !== 'string') return res.status(400).json({error:'Enter username and password'});
  const user = getUser(username.trim());
  if (!user || !bcrypt.compareSync(password, user.password_hash)) return res.status(401).json({error:'Invalid credentials'});
  req.session.regenerate(err => {
    if (err) return res.status(500).json({error:'Session error'});
    req.session.user = {id:user.id, username:user.username, role:user.role};
    res.json({user:req.session.user});
  });
});
app.post('/api/logout', auth, (req,res) => req.session.destroy(() => res.json({ok:true})));
app.get('/api/me', auth, (req,res) => res.json({user:req.session.user}));
app.get('/api/users', auth, (req,res) => {
  if (!rolesCanCreate.includes(req.session.user.role)) return res.status(403).json({error:'Forbidden'});
  const rows = db.prepare('SELECT id,username,role,created_at FROM users ORDER BY id').all();
  res.json({users:rows});
});
app.post('/api/users', auth, (req,res) => {
  const actor = req.session.user;
  const {username,password,role} = req.body || {};
  if (!canCreateRole(actor,role)) return res.status(403).json({error:'Role cannot create this account'});
  if (typeof username !== 'string' || !/^[a-zA-Z0-9_.-]{3,24}$/.test(username)) return res.status(400).json({error:'Username: 3–24 letters/numbers/._-'});
  if (typeof password !== 'string' || password.length < 12) return res.status(400).json({error:'Password must be at least 12 characters'});
  try {
    db.prepare('INSERT INTO users(username,password_hash,role) VALUES(?,?,?)').run(username, bcrypt.hashSync(password,12),role);
    res.status(201).json({ok:true});
  } catch { res.status(409).json({error:'Username already exists'}); }
});
app.get('/api/lab/status', auth, (req,res) => res.json({status:'ready',scope:'local safe simulation',user:req.session.user}));
app.use((err,req,res,next) => { console.error(err); res.status(500).json({error:'Internal server error'}); });
const port = process.env.PORT || 3000;
app.listen(port, () => console.log(`NIGHTMARE running at http://localhost:${port}`));
