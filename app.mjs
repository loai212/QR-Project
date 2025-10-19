(async () => {
  const dotenv = await import('dotenv');
  dotenv.config();

  const express = (await import('express')).default;
  const path = await import('path');
  const { fileURLToPath } = await import('url');
  const ejs = await import('ejs');
  const bodyParser = (await import('body-parser')).default;
  const qr = await import('qr-image');
  const session = (await import('express-session')).default;
  const passport = (await import('passport')).default;
  const { Strategy: GoogleStrategy } = await import('passport-google-oauth20');
  const pkg = await import('pg');
  const connectPgSimple = (await import('connect-pg-simple')).default;
  const bcrypt = await import('bcrypt');

  const app = express();
  const port = process.env.PORT || 3000;

  const { Pool } = pkg;
  const pool = new Pool({
    host: process.env.PG_HOST,
    port: process.env.PG_PORT,
    user: process.env.PG_USER,
    password: process.env.PG_PASSWORD,
    database: process.env.PG_DATABASE,
    ssl: { rejectUnauthorized: false }
  });

  const pgSession = connectPgSimple(session);
  app.use(session({
    store: new pgSession({ pool }),
    secret: process.env.SESSION_SECRET || 'fallback-secret',
    resave: false,
    saveUninitialized: false,
  }));

  app.use(passport.initialize());
  app.use(passport.session());

  const __dirname = path.dirname(fileURLToPath(import.meta.url));
  app.set('views', path.join(__dirname, 'views'));
  app.set('view engine', 'ejs');
  app.use(express.static('public'));
  app.use(bodyParser.urlencoded({ extended: false }));

  passport.use(new GoogleStrategy({
    clientID: process.env.GOOGLE_CLIENT_ID,
    clientSecret: process.env.GOOGLE_CLIENT_SECRET,
    callbackURL: '/auth/google/callback',
  }, async (accessToken, refreshToken, profile, done) => {
    const { id, displayName, emails } = profile;
    const email = emails[0].value;

    let user = await pool.query('SELECT * FROM users WHERE google_id = $1', [id]);
    if (user.rows.length === 0) {
      await pool.query('INSERT INTO users (google_id, name, email) VALUES ($1, $2, $3)', [id, displayName, email]);
      user = await pool.query('SELECT * FROM users WHERE google_id = $1', [id]);
    }
    done(null, user.rows[0]);
  }));

  passport.serializeUser((user, done) => done(null, user.id));
  passport.deserializeUser(async (id, done) => {
    const user = await pool.query('SELECT * FROM users WHERE id = $1', [id]);
    done(null, user.rows[0]);
  });

  function ensureAuthenticated(req, res, next) {
    const user = req.user || req.session.user;
    if (user) return next();
    res.redirect('/login');
  }

  app.get('/', (req, res) => {
    res.render('index', { user: req.user || req.session.user || null });
  });

  app.get('/auth/google', passport.authenticate('google', { scope: ['profile', 'email'] }));
  app.get('/auth/google/callback', passport.authenticate('google', {
    failureRedirect: '/login',
    successRedirect: '/dashboard',
  }));

  app.get('/register', (req, res) => {
    res.render('register', { error: null });
  });

  app.post('/register', async (req, res) => {
    const { name, email, password } = req.body;
    const hashed = await bcrypt.hash(password, 10);

    try {
      await pool.query(
        'INSERT INTO users (google_id, email, name, password) VALUES ($1, $2, $3, $4)',
        [null, email, name, hashed]
      );
      res.redirect('/login');
    } catch (err) {
      console.error('Registration error:', err);
      res.render('register', { error: 'Email already exists or invalid input.' });
    }
  });

  app.get('/login', (req, res) => {
    res.render('login', { error: null });
  });

  app.get('/test', (req, res) => {
    res.send('✅ Test route is working');
  });

  app.post('/login', async (req, res) => {
    const { email, password } = req.body;
    const result = await pool.query('SELECT * FROM users WHERE email = $1', [email]);
    const user = result.rows[0];
    if (user && user.password && await bcrypt.compare(password, user.password)) {
      req.session.user = user;
      res.redirect('/dashboard');
    } else {
      res.render('login', { error: 'Invalid email or password.' });
    }
  });

  app.get('/dashboard', ensureAuthenticated, async (req, res) => {
    const user = req.user || req.session.user;
    const result = await pool.query('SELECT * FROM qr_codes WHERE user_id = $1 ORDER BY created_at DESC', [user.id]);
    res.render('dashboard', { user, qrs: result.rows });
  });

  app.post('/generate', ensureAuthenticated, async (req, res) => {
    const data = req.body.data;
    const user = req.user || req.session.user;
    const qrCode = qr.image(data, { type: 'png' });

    await pool.query(
      'INSERT INTO qr_codes (user_id, content) VALUES ($1, $2)',
      [user.id, data]
    );

    res.type('png');
    qrCode.pipe(res);
  });

  app.get('/logout', (req, res) => {
    req.logout(() => {
      req.session.destroy(() => res.redirect('/'));
    });
  });

  app.listen(port, () => {
    console.log(`Server running on port ${port}`);
  });
})();
