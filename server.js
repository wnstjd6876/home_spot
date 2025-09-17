import compression from 'compression'
import path from 'path';
import dotenv from 'dotenv';
import express from 'express';
import session from 'express-session';
import mysql from 'mysql2/promise';
import bcrypt from 'bcrypt';
import multer from 'multer';
import crypto from 'crypto';
import fs from 'fs';
import { fileURLToPath } from 'url';
import { SESv2Client, SendEmailCommand, GetAccountCommand } from '@aws-sdk/client-sesv2';
import axios from 'axios';

/* ---------- ESM __dirname ---------- */
const __filename = fileURLToPath(import.meta.url);
const __dirname  = path.dirname(__filename);
const BASE_URL = process.env.APP_BASE_URL || 'http://localhost:3000';


function sha256Hex(s) {
  return crypto.createHash('sha256').update(s).digest('hex');
}
/* ---------- ENV ---------- */
dotenv.config({ path: path.resolve(__dirname, '.env'), override: true });

/* ---------- APP & MIDDLEWARE ---------- */
const app = express();
app.use(compression({
  threshold: 1024, // 1KB 이상만 압축(작은 응답은 CPU 낭비 방지)
  filter: (req, res) => {
    // 필요시 특정 요청은 건너뛰기 (ex. 헤더로 비활성화)
    if (req.headers['x-no-compress']) return false;
    return compression.filter(req, res); // 기본 필터: text/*, json 등만 압축
  },  
}));
app.use(express.urlencoded({ extended: true, limit: '15mb' }));
app.use(express.json({ limit: '15mb' }));


app.use(session({ 
  secret: process.env.SESSION_SECRET || 'change-this-secret',
  resave: false,
  saveUninitialized: false,
  cookie: { httpOnly: true, sameSite: 'lax' }
}));

/* ---------- STATIC ---------- */
app.use(express.static(path.join(__dirname, 'public')));
app.use('/uploads', express.static(path.join(__dirname, 'uploads')));

/* ---------- UPLOADS (static + multer) ---------- */
const uploadsDir = path.join(__dirname, 'uploads');
if (!fs.existsSync(uploadsDir)) fs.mkdirSync(uploadsDir, { recursive: true });
app.use('/uploads', express.static(uploadsDir));

const storage = multer.diskStorage({
  destination: (req, file, cb) => cb(null, uploadsDir),
  filename: (req, file, cb) => {
    const ext = path.extname(file.originalname);
    const base = path.basename(file.originalname, ext).replace(/[^a-zA-Z0-9_-]/g, '');
    cb(null, `${Date.now()}_${base}${ext}`);
  }
});
const upload = multer({
  storage,
  limits: { fileSize: 5 * 1024 * 1024 },
  fileFilter: (req, file, cb) => {
    if (file.mimetype && file.mimetype.startsWith('image/')) cb(null, true);
    else cb(new Error('이미지 파일만 업로드 가능합니다.'));
  }
});

/* ---------- DB POOL ---------- */
const pool = mysql.createPool({
  host: process.env.DB_HOST || '127.0.0.1',
  port: Number(process.env.DB_PORT) || 3306,
  user: process.env.DB_USER || 'appuser',
  password: process.env.DB_PASS || '',
  database: process.env.DB_NAME || 'homespot',
  waitForConnections: true,
  connectionLimit: 10,
  queueLimit: 0
});

/* ---------- DB PING (Top-level await in ESM) ---------- */
try {
  const [r] = await pool.query('SELECT 1');
  console.log('[DB] ping ok:', r[0]);
} catch (e) {
  console.error('[DB] ping failed:', e.message);
}

/* ---------- AWS Credentials (conditional session token) ---------- */
const keyId = process.env.AWS_ACCESS_KEY_ID || '';
const hasToken = !!process.env.AWS_SESSION_TOKEN;
const isTempKey = keyId.startsWith('ASIA'); // temporary creds start with ASIA, permanent with AKIA
const creds = isTempKey && hasToken
  ? { accessKeyId: keyId, secretAccessKey: process.env.AWS_SECRET_ACCESS_KEY || '', sessionToken: process.env.AWS_SESSION_TOKEN }
  : { accessKeyId: keyId, secretAccessKey: process.env.AWS_SECRET_ACCESS_KEY || '' };

console.log('[AWS ENV]', {
  region: process.env.AWS_REGION || 'ap-northeast-2',
  key_prefix: keyId ? keyId.slice(0,4) : null,
  key_len: keyId.length,
  using_session_token: isTempKey && hasToken
});

/* ---------- SES Client ---------- */
const ses = new SESv2Client({
  region: process.env.AWS_REGION || 'ap-northeast-2',
  credentials: creds
});

/* ---------- ROUTES ---------- */
app.get('/', (req, res) => res.redirect('/login.html'));

// 세입자 회원가입 (파일 없음)
app.post('/signup', upload.none(), async (req, res) => {
  try {
    const username        = (req.body.username || '').trim();
    const email           = (req.body.email || '').trim();
    const nickname        = (req.body.nickname || '').trim();
    const password        = req.body.password || '';
    const confirmPassword = req.body.confirmPassword || '';

    if (!username || !email || !password || !confirmPassword) {
      return res.status(400).send('필수 입력 누락');
    }
    if (password !== confirmPassword) {
      return res.status(400).send('비밀번호가 일치하지 않습니다');
    }

    // 중복 체크
    {
      const [[{ cnt }]] = await pool.query(
        'SELECT COUNT(*) AS cnt FROM users WHERE user_name=?',
        [username]
      );
      if (cnt > 0) return res.status(409).send('이미 존재하는 아이디입니다');
    }
    {
      const [[{ cnt }]] = await pool.query(
        'SELECT COUNT(*) AS cnt FROM users WHERE LOWER(email)=LOWER(?)',
        [email]
      );
      if (cnt > 0) return res.status(409).send('이미 존재하는 이메일입니다');
    }

    // 비밀번호 해시 + INSERT
    const hash = await bcrypt.hash(password, 12);
    await pool.query(
      'INSERT INTO users (user_name, email, password, nickname) VALUES (?, ?, ?, ?)',
      [username, email, hash, nickname || null]
    );

    return res.status(200).end(); // 프론트 fetch는 res.ok로 성공 처리
  } catch (err) {
    console.error('Tenant signup error:', err);
    return res.status(500).send('회원가입 실패');
  }
});



/* -- 로그인(관리자/중개사/세입자) -- */
app.post('/login', async (req, res) => {
  try {
    const { username, password } = req.body;

    // 관리자
    {
      const [rows] = await pool.query(
        "SELECT admin_id, username, password FROM admins WHERE username=? LIMIT 1",
        [username]
      );
      if (rows.length) {
        const admin = rows[0];
        const isHash = typeof admin.password === 'string' && admin.password.startsWith('$2');
        const ok = isHash ? await bcrypt.compare(password, admin.password) : (password === admin.password);
        if (!ok) return res.send("<script>alert('비밀번호가 올바르지 않습니다');history.back();</script>");
        req.session.user = { role: 'admin', id: admin.admin_id, username: admin.username };
        return res.redirect('/admin');
      }
    }

    // 중개사(승인 필요)
    {
      const [rows] = await pool.query(
        "SELECT agent_id AS agent_id, email, agent_name AS name, password, license_status FROM agents WHERE agent_name=? LIMIT 1",
        [username]
      );
      if (rows.length) {
        const a = rows[0];
        if (a.license_status !== 'approved') {
          return res.send("<script>alert('관리자 승인 대기 중입니다');history.back();</script>");
        }
        const ok = await bcrypt.compare(password, a.password);
        if (!ok) return res.send("<script>alert('비밀번호가 올바르지 않습니다');history.back();</script>");
        req.session.user = { role: 'agent', id: a.agent_id, email: a.email, name: a.name };
        return res.redirect('/agent');
      }
    }

    // 세입자
    {
      const [rows] = await pool.query(
        "SELECT user_id AS user_id, email, user_name AS name, password FROM users WHERE user_name=? LIMIT 1",
        [username]
      );
      if (!rows.length) {
        return res.send("<script>alert('사용자를 찾을 수 없습니다');history.back();</script>");
      }
      const u = rows[0];
      const ok = await bcrypt.compare(password, u.password);
      if (!ok) return res.send("<script>alert('비밀번호가 올바르지 않습니다');history.back();</script>");
      req.session.user = { role: 'tenant', id: u.user_id, email: u.email, name: u.name };
      return res.redirect('/tenant');
    }
  } catch (err) {
    console.error('Login error:', err.message);
    res.send("<script>alert('로그인 실패');history.back();</script>");
  }
});

/* -- 대시보드 -- */
app.get('/admin', (req, res) => {
  if (!req.session.user || req.session.user.role !== 'admin') return res.redirect('/login.html');
  res.sendFile(path.join(__dirname, 'public', 'main_admin.html'));
});
app.get('/agent', (req, res) => {
  if (!req.session.user || req.session.user.role !== 'agent') return res.redirect('/login.html');
  res.sendFile(path.join(__dirname, 'public', 'mainpageagent.html'));
});
app.get('/tenant', (req, res) => {
  if (!req.session.user || req.session.user.role !== 'tenant') return res.redirect('/login.html');
  res.sendFile(path.join(__dirname, 'public', 'tenant_main.html'));
});

app.get('/logout', (req, res) => {
  req.session.destroy(() => res.redirect('/login.html'));
});

// 중개사 회원가입 (이미지 1장 필수)
app.post(
  '/broker-signup',
  (req, res, next) => {
    upload.single('license')(req, res, (err) => {
      if (err) {
        console.error('Multer error:', err);
        // fileFilter 실패 시 err.message에 "이미지 파일만 업로드 가능합니다."가 들어옴
        return res.status(400).send(err.message || '업로드 실패');
      }
      next();
    });
  },
  async (req, res) => {
    try {
      const agentName       = (req.body.username || req.body.name || '').trim();
      const email           = (req.body.email || '').trim();
      const nickname        = (req.body.nickname || '').trim();
      const password        = req.body.password || '';
      const confirmPassword = req.body.confirmPassword || '';
      

      if (!agentName || !email || !password || !confirmPassword) {
        return res.status(400).send('필수 입력 누락');
      }
      if (password !== confirmPassword) {
        return res.status(400).send('비밀번호가 일치하지 않습니다');
      }
      if (!req.file) {
        return res.status(400).send('자격증 이미지를 업로드하세요');
      }

      // 중복 체크
      {
        const [[{ cnt }]] = await pool.query(
          'SELECT COUNT(*) AS cnt FROM agents WHERE agent_name=?',
          [agentName]
        );
        if (cnt > 0) return res.status(409).send('이미 존재하는 아이디입니다');
      }
      {
        const [[{ cnt }]] = await pool.query(
          'SELECT COUNT(*) AS cnt FROM agents WHERE LOWER(email)=LOWER(?)',
          [email]
        );
        if (cnt > 0) return res.status(409).send('이미 존재하는 이메일입니다');
      }

      const hash = await bcrypt.hash(password, 12);

      // diskStorage를 사용 중이면 filename이 존재합니다.
      // 정적 제공을 /uploads로 하고 있다면 URL도 함께 만들어 둡니다.
      const licenseFile = req.file.filename;        // 파일명만
      const licenseUrl  = licenseFile;

      await pool.query(
        "INSERT INTO agents (agent_name, email, password, nickname, license_url, license_status) VALUES (?, ?, ?, ?, ?, ?)",
        [agentName, email, hash, nickname || null, licenseUrl, 'pending']
      );

      return res.status(200).end();
    } catch (err) {
      console.error('Broker signup error:', err);
      return res.status(500).send('회원가입 실패');
    }
  }
);

/* -- 승인/거절 & 목록 API -- */
app.post('/approve-broker/:id', async (req, res) => {
  try {
    const { id } = req.params;
    const [rows] = await pool.query("SELECT email FROM agents WHERE agent_id=?", [id]);
    if (!rows.length) return res.status(404).send('중개사를 찾을 수 없습니다.');

    await pool.query("UPDATE agents SET license_status='approved' WHERE agent_id=?", [id]);
    await sendEmail({ to: rows[0].email, subject: '승인 완료', text: '중개사 회원가입 요청이 승인되었습니다.' });
    res.status(200).send('승인 완료');
  } catch (err) {
    console.error('Approve error:', err.message);
    res.status(500).send('승인 실패');
  }
});

app.post('/reject-broker/:id', async (req, res) => {
  try {
    const { id } = req.params;
    const [rows] = await pool.query("SELECT email FROM agents WHERE agent_id=?", [id]);
    if (!rows.length) return res.status(404).send('중개사를 찾을 수 없습니다.');

    await pool.query("UPDATE agents SET license_status='rejected' WHERE agent_id=?", [id]);
    await sendEmail({ to: rows[0].email, subject: '거절 안내', text: '중개사 회원가입 요청이 거절되었습니다.' });
    res.status(200).send('거절 완료');
  } catch (err) {
    console.error('Reject error:', err.message);
    res.status(500).send('거절 실패');
  }
});

app.get('/admin/broker-requests', async (req, res) => {
  try {
    if (!req.session.user || req.session.user.role !== 'admin') {
      return res.status(403).send('관리자 권한이 필요합니다.');
    }
    const [rows] = await pool.query(
      "SELECT agent_id AS agent_id, agent_name AS name, email, license_url, license_status FROM agents WHERE license_status='pending'"
    );
    res.json(rows);
  } catch (err) {
    console.error('List error:', err.message);
    res.status(500).send('서버 오류');
  }
});

/* -- Diagnostics: SES GetAccount -- */
app.get('/__ses_account', async (req, res) => {
  try {
    const out = await ses.send(new GetAccountCommand({}));
    res.json({ ok: true, dedicatedIpAutoWarmupEnabled: out.DedicatedIpAutoWarmupEnabled ?? null, enforcementStatus: out.EnforcementStatus ?? null });
  } catch (e) {
    res.status(500).json({ ok: false, error: e.message });
  }
});

// -- 아이디 찾기 API --
app.post('/find-id', async (req, res) => {
  try {
    const { email } = req.body;
    if (!email) return res.send("<script>alert('이메일을 입력해주세요');history.back();</script>");

    // users, agents 양쪽에서 조회 (로그인 아이디는 name 컬럼을 사용 중)
    const [uRows] = await pool.query("SELECT user_name AS name FROM users WHERE email=?", [email]);
    const [aRows] = await pool.query("SELECT agent_name AS name FROM agents WHERE email=?", [email]);

    // 메일 본문 구성
    const lines = [];
    if (uRows.length) lines.push(`세입자(tenant) 아이디: ${uRows.map(r=>r.name).join(', ')}`);
    if (aRows.length) lines.push(`중개사(agent) 아이디: ${aRows.map(r=>r.name).join(', ')}`);

    // 존재 여부와 관계없이 동일 응답(계정 유추 방지). 존재하면 메일 발송
    if (lines.length) {
      await sendEmail({
        to: email,
        subject: '[홈스팟] 아이디 안내',
        text: `요청하신 아이디입니다.\n\n${lines.join('\n')}\n\n만약 본인이 아니라면 이 메일을 무시하세요.`
      });
    }
    return res.send("<script>alert('입력하신 이메일로 안내를 보냈습니다(존재하는 경우)');location.href='/login.html';</script>");
  } catch (err) {
    console.error('find-id error:', err.message);
    return res.send("<script>alert('처리 중 오류가 발생했습니다');history.back();</script>");
  }
});

// -- 비밀번호 재설정 요청 API --
app.post('/find-pwd', async (req, res) => {
  try {
    const { email, userid } = req.body; // userid = 아이디(name)
    if (!email || !userid) {
      return res.send("<script>alert('아이디와 이메일을 모두 입력해주세요');history.back();</script>");
    }

    let userType = null;
    let userId = null;

    // users 우선
    {
      const [rows] = await pool.query(
        "SELECT user_id AS id FROM users WHERE email=? AND user_name=? LIMIT 1",
        [email, userid]
      );
      if (rows.length) {
        userType = 'tenant';
        userId = rows[0].id;
      }
    }

    // 없으면 agents
    if (!userId) {
      const [rows] = await pool.query(
        "SELECT agent_id AS id FROM agents WHERE email=? AND agent_name=? LIMIT 1",
        [email, userid]
      );
      if (rows.length) {
        userType = 'agent';
        userId = rows[0].id;
      }
    }

    // 계정 유무와 관계없이 같은 응답(유출 방지)
    if (userId) {
      const token = crypto.randomBytes(32).toString('hex');
      const tokenHash = sha256Hex(token);
      const expiresAt = new Date(Date.now() + 60 * 60 * 1000); // 1시간

      await pool.query(
        "INSERT INTO password_resets (user_type, user_id, email, token_hash, expires_at) VALUES (?, ?, ?, ?, ?)",
        [userType, userId, email, tokenHash, expiresAt]
      );

      const link = `${BASE_URL}/reset-password?token=${token}`;
      await sendEmail({
        to: email,
        subject: '[홈스팟] 비밀번호 재설정 링크',
        text: `아래 링크에서 1시간 이내에 새 비밀번호를 설정하세요:\n${link}\n\n본인이 요청하지 않았다면 무시하세요.`
      });
    }

    return res.send("<script>alert('입력하신 정보와 일치하는 계정이 존재하는 경우, 재설정 링크를 이메일로 보냈습니다');location.href='/login.html';</script>");
  } catch (err) {
    console.error('find-pwd error:', err.message);
    return res.send("<script>alert('처리 중 오류가 발생했습니다');history.back();</script>");
  }
});
app.get("/reset-password", (req, res) => {
  res.sendFile(path.join(process.cwd(), "public", "reset_password.html"));
});
// 비밀번호 재설정 적용
app.post('/reset-password', async (req, res) => {
  try {
    const { token, password, confirmPassword } = req.body;
    if (!token) return res.send("<script>alert('토큰이 없습니다');history.back();</script>");
    if (!password || password !== confirmPassword) {
      return res.send("<script>alert('비밀번호가 일치하지 않습니다');history.back();</script>");
    }

    const tokenHash = sha256Hex(token);
    const [rows] = await pool.query(
      "SELECT id, user_type, user_id, expires_at, used FROM password_resets WHERE token_hash=? LIMIT 1",
      [tokenHash]
    );
    if (!rows.length) return res.send("<script>alert('유효하지 않은 링크입니다');location.href='/login.html';</script>");

    const r = rows[0];
    if (r.used) return res.send("<script>alert('이미 사용된 링크입니다');location.href='/login.html';</script>");
    if (new Date(r.expires_at) < new Date()) {
      return res.send("<script>alert('링크가 만료되었습니다');location.href='/login.html';</script>");
    }

    // 비밀번호 해시 후 덮어쓰기
    const hash = await bcrypt.hash(password, 12);
    if (r.user_type === 'tenant') {
      await pool.query("UPDATE users SET password=? WHERE user_id=?", [hash, r.user_id]);
    } else {
      await pool.query("UPDATE agents SET password=? WHERE agent_id=?", [hash, r.user_id]);
    }

    // 토큰 사용 처리 및 같은 이메일의 다른 미사용 토큰 무효화(선택)
    await pool.query("UPDATE password_resets SET used=1, used_at=NOW() WHERE id=?", [r.id]);

    res.send("<script>alert('비밀번호가 변경되었습니다. 로그인 해주세요.');location.href='/login.html';</script>");
  } catch (err) {
    console.error('reset-password error:', err.message);
    return res.send("<script>alert('처리 중 오류가 발생했습니다');history.back();</script>");
  }
});

// 프로필페이지
app.get('/profile', (req, res) => {
  if (!req.session.user) return res.redirect('/login.html');
  res.sendFile(path.join(__dirname, 'public', 'profile_setting.html'));
});

// 현재 유저 조회 api (admin/agent/tenant 공통) — 이 한 개만 남겨
app.get('/api/me', async (req, res) => {
  try {
    const u = req.session?.user;
    if (!u) {
      // 로그인 안 함
      return res.json({ ok:false });
    }

    // 1) 관리자
    if (u.role === 'admin') {
      return res.json({
        ok: true,
        id: u.id,
        role: 'admin',
        nickname: null,
        profile_url: null
      });
    }

    // 2) 중개사
    if (u.role === 'agent') {
      const [[row]] = await pool.query(
        "SELECT nickname, profile_url FROM agents WHERE agent_id=? LIMIT 1",
        [u.id]
      );
      return res.json({
        ok: true,
        id: u.id,
        role: 'agent',
        nickname: row?.nickname ?? null,
        profile_url: row?.profile_url ?? null
      });
    }

    // 3) 일반 사용자(세입자)
    const [[row]] = await pool.query(
      "SELECT nickname, profile_url FROM users WHERE user_id=? LIMIT 1",
      [u.id]
    );
    return res.json({
      ok: true,
      id: u.id,
      role: 'tenant',
      nickname: row?.nickname ?? null,
      profile_url: row?.profile_url ?? null
    });
  } catch (e) {
    console.error('GET /api/me', e);
    res.status(500).json({ ok:false });
  }
});



//닉네임 저장 api
app.post('/api/profile/nickname', async (req, res) => {
  try {
    if (!req.session.user) return res.status(401).json({ ok:false });
    const { nickname } = req.body;
    if (!nickname || nickname.length > 64) {
      return res.status(400).json({ ok:false, message:'닉네임 길이 확인' });
    }

    const u = req.session.user;
    if (u.role === 'agent') {
      await pool.query("UPDATE agents SET nickname=? WHERE agent_id=?", [nickname, u.id]);
    } else {
      await pool.query("UPDATE users SET nickname=? WHERE user_id=?", [nickname, u.id]);
    }
    res.json({ ok:true });
  } catch (e) {
    console.error(e);
    res.status(500).json({ ok:false });
  }
});

//프로필사진 설정
app.post('/api/profile/photo', upload.single('photo'), async (req, res) => {
  try {
    if (!req.session.user) return res.status(401).json({ ok:false });
    if (!req.file) return res.status(400).json({ ok:false, message:'파일 없음' });

    const filename = req.file.filename; // /uploads/{filename} 로 정적 제공 중
    const u = req.session.user;

    if (u.role === 'agent') {
      await pool.query("UPDATE agents SET profile_url=? WHERE agent_id=?", [filename, u.id]);
    } else {
      await pool.query("UPDATE users SET profile_url=? WHERE user_id=?", [filename, u.id]);
    }
    res.json({ ok:true, url: filename });
  } catch (e) {
    console.error(e);
    res.status(500).json({ ok:false, message:'업로드 실패' });
  }
});

//회원 탈퇴
app.post('/api/profile/delete', async (req, res) => {
  try {
    if (!req.session.user) return res.status(401).json({ ok:false });
    const { confirm } = req.body;
    if (confirm !== '탈퇴합니다') return res.status(400).json({ ok:false, message:'확인 문구 불일치' });

    const u = req.session.user;
    if (u.role === 'agent') {
      await pool.query("DELETE FROM agents WHERE agent_id=?", [u.id]);
    } else {
      await pool.query("DELETE FROM users WHERE user_id=?", [u.id]);
    }
    req.session.destroy(() => {});
    res.json({ ok:true });
  } catch (e) {
    console.error(e);
    res.status(500).json({ ok:false });
  }
});

// 매물 등록 (도로명/지번 선택 + 폴백 + 키워드 보조 + 좌표 안전장치 +
// GeoJSON 우선 + WKT(long-lat / lat-long) 자동 재시도 + lot_no NOT NULL 대응)
app.post('/api/listings', async (req, res) => {
  try {
    if (!req.session.user || req.session.user.role !== 'agent') {
      return res.status(401).json({ ok:false, message:'unauthorized' });
    }
    const agentId = req.session.user.id;

    // 1) 바디 파싱
    const {
      title = '',
      description = '',
      property_type_ui = '',
      deal_type_ui = '',
      sigungu = '',
      road_name = '',
      lot_no = '',
      dong = '',
      jibun_no = '',
      address_mode = 'road',
      area_m2 = null, gross_area_m2 = null, land_area_m2 = null, land_share_m2 = null,
      floor = null, built_year = null,
      price_10k = null,
      deposit_10k = null,
      rent_annual_10k = null
    } = req.body || {};

    if (!title.trim() || !property_type_ui || !deal_type_ui || !sigungu.trim() || !description) {
      return res.status(400).json({ ok:false, message:'필수 입력 누락' });
    }

    // 2) 주소 조합 + lot_no 보정(지번 모드일 때 lot_no 필요)
    let fullAddr = '';
    let lotNoForDb = lot_no; // listings.lot_no는 NOT NULL
    if (address_mode === 'road') {
      fullAddr = `${sigungu} ${road_name} ${lot_no}`.trim();
      if (!lotNoForDb) return res.status(400).json({ ok:false, message:'건물번호(번지) 필수' });
    } else {
      fullAddr = `${sigungu} ${dong} ${jibun_no}`.trim();
      lotNoForDb = jibun_no || lot_no; // 지번을 lot_no에 대입해 NOT NULL 충족
      if (!lotNoForDb) return res.status(400).json({ ok:false, message:'지번(번지) 필수' });
    }

    // 3) 좌표 구하기 (카카오) + 폴백 + 키워드
    const kakaoKey = process.env.KAKAO_REST_KEY || '';
    if (!kakaoKey) return res.status(500).json({ ok:false, message:'서버 지오코딩 키 미설정(KAKAO_REST_KEY)' });

    const kakaoGet = async (url) =>
      axios.get(url, { headers: { Authorization: `KakaoAK ${kakaoKey}` }, timeout: 6000 });

    const parseDoc = (doc) => {
      if (doc?.address)      return [Number(doc.address.y), Number(doc.address.x)];       // [lat,lng]
      if (doc?.road_address) return [Number(doc.road_address.y), Number(doc.road_address.x)];
      return [null, null];
    };

    let lat = null, lng = null;
    const tried = [];

    // A. 선택 모드
    try {
      const urlA = `https://dapi.kakao.com/v2/local/search/address.json?query=${encodeURIComponent(fullAddr)}`;
      const outA = await kakaoGet(urlA);
      tried.push({ type:`address(${address_mode})`, q: fullAddr, count: outA?.data?.documents?.length || 0 });
      const docA = outA?.data?.documents?.[0];
      if (docA) [lat, lng] = parseDoc(docA);
    } catch (e) {
      tried.push({ type:`address(${address_mode})-err`, q: fullAddr, err: e?.message || String(e) });
    }

    // B. 반대 모드 폴백
    if (!Number.isFinite(lat) || !Number.isFinite(lng)) {
      const altAddr = (address_mode === 'road')
        ? `${sigungu || ''} ${dong || ''} ${jibun_no || lot_no || ''}`.trim()
        : `${sigungu || ''} ${road_name || ''} ${lot_no || jibun_no || ''}`.trim();
      try {
        const urlB = `https://dapi.kakao.com/v2/local/search/address.json?query=${encodeURIComponent(altAddr)}`;
        const outB = await kakaoGet(urlB);
        tried.push({ type:'address(fallback)', q: altAddr, count: outB?.data?.documents?.length || 0 });
        const docB = outB?.data?.documents?.[0];
        if (docB) [lat, lng] = parseDoc(docB);
      } catch (e) {
        tried.push({ type:'address(fallback)-err', q: altAddr, err: e?.message || String(e) });
      }
    }

    // C. 키워드 보조
    if (!Number.isFinite(lat) || !Number.isFinite(lng)) {
      try {
        const urlK = `https://dapi.kakao.com/v2/local/search/keyword.json?query=${encodeURIComponent(fullAddr)}`;
        const outK = await kakaoGet(urlK);
        tried.push({ type:'keyword', q: fullAddr, count: outK?.data?.documents?.length || 0 });
        const docK = outK?.data?.documents?.[0];
        if (docK?.x && docK?.y) { lat = Number(docK.y); lng = Number(docK.x); }
      } catch (e) {
        tried.push({ type:'keyword-err', q: fullAddr, err: e?.message || String(e) });
      }
    }

    // 좌표 안전장치(뒤집힘 자동 보정)
    if (Number.isFinite(lat) && Number.isFinite(lng)) {
      const latOk = Math.abs(lat) <= 90;
      const lonOk = Math.abs(lng) <= 180;
      if (!latOk && lonOk && Math.abs(lng) <= 90 && Math.abs(lat) <= 180) {
        const t = lat; lat = lng; lng = t;
      }
    }

    // 소수 6자리(테이블 lat/lng 정밀도에 맞춤)
    if (Number.isFinite(lat)) lat = Number(lat.toFixed(6));
    if (Number.isFinite(lng)) lng = Number(lng.toFixed(6));

    console.log('[GEOCODE]', { address_mode, fullAddr, tried, lat, lng });
    if (!Number.isFinite(lat) || !Number.isFinite(lng)) {
      return res.status(400).json({ ok:false, message:`좌표 계산 실패(주소 확인 필요): ${fullAddr}` });
    }

    // 4) 가격 매핑
    const property_type = String(property_type_ui);
    const deal_type = String(deal_type_ui);
    let price_sale_10k = null, depositVal_10k = null, rent_10k = null, rent_pay_cycle = null, rentAnnual_10k = null;

    if (deal_type === 'sale') {
      price_sale_10k = Number(price_10k) || null;
    } else if (deal_type === 'jeonse') {
      price_sale_10k = Number(price_10k) || null; // 설계에 맞게 유지
    } else if (deal_type === 'monthly') {
      rent_10k = Number(price_10k) || null;
      rent_pay_cycle = 'monthly';
      depositVal_10k = Number(deposit_10k) || null;
    } else if (deal_type === 'yearly') {
      depositVal_10k = Number(deposit_10k) || null;
      rentAnnual_10k = Number(rent_annual_10k) || null;
      rent_pay_cycle = 'yearly';
    }

    // 5) INSERT — GeoJSON 우선, 실패 시 WKT(long-lat) → WKT(lat-long) 재시도
    const baseCols = `
      INSERT INTO listings
        (agent_id, title, description,
         property_type, deal_type,
         sigungu, road_name, lot_no, dong,
         area_m2, gross_area_m2, land_share_m2, land_area_m2,
         floor, built_year,
         price_sale_10k, deposit_10k, rent_10k, rent_pay_cycle, rent_annual_10k,
         full_addr, lat, lng, coord, status)
      VALUES
        (?, ?, ?,
         ?, ?,
         ?, ?, ?, ?,
         ?, ?, ?, ?,
         ?, ?,
         ?, ?, ?, ?, ?,
         ?, ?, ?, /* COORD_PLACEHOLDER */, 'active')
    `;

    const commonParams = [
      agentId, title, description,
      property_type, deal_type,
      sigungu || null, (road_name || null), (lotNoForDb || null), (dong || null),
      area_m2, gross_area_m2, land_share_m2, land_area_m2,
      floor, built_year,
      price_sale_10k, depositVal_10k, rent_10k, rent_pay_cycle, rentAnnual_10k,
      fullAddr, lat, lng
    ];

    // 시도 1: GeoJSON (좌표계는 GeoJSON 표준 [lon, lat], MySQL은 기본 SRID 4326)
    const geojson = JSON.stringify({ type: 'Point', coordinates: [lng, lat] });
    try {
      const sql1 = baseCols.replace('/* COORD_PLACEHOLDER */', `ST_GeomFromGeoJSON(?)`);
      const [r1] = await pool.query(sql1, [...commonParams, geojson]);
      return res.json({ ok:true, id: r1.insertId, axis:'geojson[lng,lat]' });
    } catch (e1) {
      console.warn('[INSERT coord attempt#1 GeoJSON failed]', e1.code || e1.sqlMessage || e1.message);
    }

    // 시도 2: WKT (long-lat: POINT(lng lat)) — 표준 WKT XY
    try {
      const sql2 = baseCols.replace('/* COORD_PLACEHOLDER */', `ST_GeomFromText(?, 4326)`);
      const wkt2 = `POINT(${lng} ${lat})`;
      const [r2] = await pool.query(sql2, [...commonParams, wkt2]);
      return res.json({ ok:true, id: r2.insertId, axis:'wkt[lon lat]' });
    } catch (e2) {
      console.warn('[INSERT coord attempt#2 WKT lon-lat failed]', e2.code || e2.sqlMessage || e2.message);
    }

    // 시도 3: WKT (lat-long: POINT(lat lng)) — 일부 환경 축순서 강제
    try {
      const sql3 = baseCols.replace('/* COORD_PLACEHOLDER */', `ST_GeomFromText(?, 4326)`);
      const wkt3 = `POINT(${lat} ${lng})`;
      const [r3] = await pool.query(sql3, [...commonParams, wkt3]);
      return res.json({ ok:true, id: r3.insertId, axis:'wkt[lat lon]' });
    } catch (e3) {
      console.warn('[INSERT coord attempt#3 WKT lat-lon failed]', e3.code || e3.sqlMessage || e3.message);
    }

    // 모두 실패
    return res.status(500).json({ ok:false, message:'좌표 생성 실패 - DB GIS 함수/축순서 호환' });
  } catch (e) {
    console.error('create listing error:', e);
    return res.status(500).json({ ok:false, message:'등록 실패' });
  }
});



// 내 매물 목록 (검색 + 페이지네이션)
app.get('/api/my-listings', async (req, res) => {
  try {
    if (!req.session.user || req.session.user.role !== 'agent') {
      return res.status(401).json({ ok:false, message:'unauthorized' });
    }
    const agentId  = req.session.user.id;
    const page     = Math.max(1, parseInt(req.query.page) || 1);
    const pageSize = Math.min(50, Math.max(1, parseInt(req.query.pageSize) || 10));
    const q        = (req.query.q || '').trim();

    const where = ['l.agent_id = ?'];
    const params = [agentId];

    if (q) {
      // 제목/설명/주소(시군구, 도로명, 지번) 검색
      where.push(`(l.title LIKE ? OR l.description LIKE ? OR l.sigungu LIKE ? OR l.road_name LIKE ? OR l.lot_no LIKE ?)`);
      const like = `%${q}%`;
      params.push(like, like, like, like, like);
    }

    const whereSql = 'WHERE ' + where.join(' AND ');
    const [[{ total }]] = await pool.query(
      `SELECT COUNT(*) AS total FROM listings l ${whereSql}`,
      params
    );

    const offset = (page - 1) * pageSize;
    const [rows] = await pool.query(
      `
      SELECT
        l.listing_id, l.title, l.description,
        l.property_type, l.deal_type,
        l.price_sale_10k, l.deposit_10k, l.rent_10k, l.rent_pay_cycle, l.rent_annual_10k,
        l.status, l.created_at,
        (SELECT li.image_url FROM listing_images li
          WHERE li.listing_id = l.listing_id ORDER BY li.image_id ASC LIMIT 1) AS main_image_url
      FROM listings l
      ${whereSql}
      ORDER BY l.created_at DESC
      LIMIT ? OFFSET ?
      `,
      [...params, pageSize, offset]
    );

    res.json({ ok:true, items:rows, total, page, pageSize });
  } catch (e) {
    console.error('my listings error:', e);
    res.status(500).json({ ok:false });
  }
});


// 이미지 업로드 (여러 장)
app.post('/api/listings/:id/images', upload.array('images', 10), async (req, res) => {
  try {
    if (!req.session.user || req.session.user.role !== 'agent') {
      return res.status(401).json({ ok:false, message:'unauthorized' });
    }
    const listingId = Number(req.params.id);
    if (!listingId || !req.files?.length) {
      return res.status(400).json({ ok:false, message:'파일 없음' });
    }

    // 소유자 검증: 이 매물이 내 것인지
    const [[own]] = await pool.query(
      'SELECT agent_id FROM listings WHERE listing_id=? LIMIT 1', [listingId]
    );
    if (!own || own.agent_id !== req.session.user.id) {
      return res.status(403).json({ ok:false, message:'forbidden' });
    }

    // DB 저장
    const vals = req.files.map(f => [listingId, f.filename]);
    await pool.query('INSERT INTO listing_images (listing_id, image_url) VALUES ?', [vals]);

    res.json({ ok:true, count: vals.length });
  } catch (e) {
    console.error('upload images error:', e.message);
    res.status(500).json({ ok:false, message:'업로드 실패' });
  }
});

// 이미지 목록
app.get('/api/listings/:id/images', async (req, res) => {
  try {
    if (!req.session.user || req.session.user.role !== 'agent') {
      return res.status(401).json({ ok:false, message:'unauthorized' });
    }
    const listingId = Number(req.params.id);
    // 내 매물만 열람
    const [[own]] = await pool.query('SELECT agent_id FROM listings WHERE listing_id=?', [listingId]);
    if (!own || own.agent_id !== req.session.user.id) {
      return res.status(403).json({ ok:false, message:'forbidden' });
    }
    const [rows] = await pool.query(
      'SELECT image_id, image_url FROM listing_images WHERE listing_id=? ORDER BY image_id', [listingId]
    );
    res.json({ ok:true, items: rows });
  } catch (e) {
    console.error(e); res.status(500).json({ ok:false });
  }
});

// 이미지 삭제
app.delete('/api/listings/:id/images/:imageId', async (req, res) => {
  try {
    if (!req.session.user || req.session.user.role !== 'agent') {
      return res.status(401).json({ ok:false, message:'unauthorized' });
    }
    const listingId = Number(req.params.id);
    const imageId   = Number(req.params.imageId);

    // 이미지 + 소유 확인
    const [[img]] = await pool.query(`
      SELECT li.image_id, li.image_url, l.agent_id
      FROM listing_images li
      JOIN listings l ON l.listing_id = li.listing_id
      WHERE li.image_id=? AND li.listing_id=? LIMIT 1
    `, [imageId, listingId]);

    if (!img || img.agent_id !== req.session.user.id) {
      return res.status(403).json({ ok:false, message:'forbidden' });
    }

    // DB 삭제
    await pool.query('DELETE FROM listing_images WHERE image_id=?', [imageId]);

    // 파일도 제거(실패해도 무시)
    const p = path.join(__dirname, 'uploads', img.image_url);
    fs.promises.unlink(p).catch(()=>{});

    res.json({ ok:true });
  } catch (e) {
    console.error(e); res.status(500).json({ ok:false });
  }
});


// 매물 삭제
app.delete('/api/listings/:id', async (req, res) => {
  try {
    if (!req.session.user || req.session.user.role !== 'agent') {
      return res.status(401).json({ ok:false, message:'unauthorized' });
    }
    const listingId = Number(req.params.id);
    const agentId   = req.session.user.id;

    // 소유권 확인 + 이미지 목록
    const [[own]] = await pool.query(
      'SELECT agent_id FROM listings WHERE listing_id=? LIMIT 1',
      [listingId]
    );
    if (!own) return res.status(404).json({ ok:false, message:'not found' });
    if (own.agent_id !== agentId) {
      return res.status(403).json({ ok:false, message:'forbidden' });
    }

    const [imgs] = await pool.query(
      'SELECT image_url FROM listing_images WHERE listing_id=?',
      [listingId]
    );

    // DB 삭제 (listing_images는 FK로 같이 지워집니다)
    await pool.query('DELETE FROM listings WHERE listing_id=?', [listingId]);

    // 물리 파일도 제거(실패는 무시)
    for (const r of imgs) {
      const p = path.join(uploadsDir, r.image_url);
      fs.promises.unlink(p).catch(()=>{});
    }

    res.json({ ok:true });
  } catch (e) {
    console.error(e);
    res.status(500).json({ ok:false });
  }
});

// 내 매물 단건 조회
app.get('/api/my-listings/:id', async (req, res) => {
  try{
    const u = req.session?.user;
    if (!u || u.role !== 'agent') return res.status(401).json({ ok:false, message:'unauthorized' });

    const id = Number(req.params.id);
    if (!Number.isFinite(id)) return res.status(400).json({ ok:false, message:'bad_id' });

    // 본인 소유 + 이미지 포함
    const [[item]] = await pool.query(
      `SELECT l.*
         FROM listings l
        WHERE l.listing_id=? AND l.agent_id=? LIMIT 1`,
      [id, u.id]
    );
    if (!item) return res.status(404).json({ ok:false, message:'not_found' });

    const [images] = await pool.query(
      `SELECT image_id, image_url FROM listing_images WHERE listing_id=? ORDER BY image_id`, [id]
    );

    return res.json({ ok:true, item: { ...item, images } });
  }catch(e){
    console.error(e);
    return res.status(500).json({ ok:false, message:'server_error' });
  }
});


app.put('/api/my-listings/:id', upload.array('images', 20), async (req, res) => {
  const conn = await pool.getConnection();
  try{
    const u = req.session?.user;
    if (!u || u.role !== 'agent') { return res.status(401).json({ ok:false, message:'unauthorized' }); }

    const id = Number(req.params.id);
    if (!Number.isFinite(id)) return res.status(400).json({ ok:false, message:'bad_id' });

    // 본인 소유 확인
    const [[own]] = await conn.query(
      'SELECT listing_id FROM listings WHERE listing_id=? AND agent_id=? LIMIT 1',
      [id, u.id]
    );
    if (!own) return res.status(404).json({ ok:false, message:'not_found' });

    // 폼 값 파싱(없는 값은 그대로 유지하고 싶으면 COALESCE 방식 or 동적 SET 생성)
    const b = req.body;
    const fields = {
      title: b.title,
      description: b.description,
      property_type: b.property_type,
      deal_type: b.deal_type,
      sigungu: b.sigungu,
      road_name: b.road_name,
      lot_no: b.lot_no,
      si: b.si, gu: b.gu, dong: b.dong,
      area_m2: b.area_m2 || null,
      gross_area_m2: b.gross_area_m2 || null,
      land_area_m2: b.land_area_m2 || null,
      floor: b.floor || null,
      built_year: b.built_year || null,
      price_sale_10k: b.price_sale_10k || null,
      deposit_10k: b.deposit_10k || null,
      rent_10k: b.rent_10k || null,
      rent_pay_cycle: b.rent_pay_cycle || null,
      status: b.status || 'active',
      full_addr: b.full_addr || null,
      lat: b.lat || null,
      lng: b.lng || null,
      // coord는 lat/lng로부터 서버에서 생성한다면 여기서 업데이트
      // coord: (b.lat && b.lng) ? conn.escape(/* ST_SRID(POINT(lng,lat),4326) */) : undefined
    };

    // 동적 SET
    const setCols = [];
    const params  = [];
    for (const [k,v] of Object.entries(fields)){
      if (v !== undefined){ setCols.push(`${k}=?`); params.push(v); }
    }
    if (!setCols.length) return res.json({ ok:true }); // 변경 없음

    await conn.beginTransaction();
    await conn.query(`UPDATE listings SET ${setCols.join(', ')} WHERE listing_id=?`, [...params, id]);

    // 새 이미지 추가(선택)
    if (Array.isArray(req.files) && req.files.length){
      const rows = req.files.map(f => [id, f.filename]); // filename → 실제 저장 정책에 맞게
      await conn.query(
        'INSERT INTO listing_images (listing_id, image_url) VALUES ?',
        [rows]
      );
    }

    await conn.commit();
    return res.json({ ok:true });
  }catch(e){
    try{ await conn.rollback(); }catch{}
    console.error(e);
    return res.status(500).json({ ok:false, message:'server_error' });
  }finally{
    conn.release();
  }
});

app.post('/api/my-listings/:id/replace', upload.array('images', 20), async (req, res) => {
  const conn = await pool.getConnection();
  try {
    const u = req.session?.user;
    if (!u || u.role !== 'agent') return res.status(401).json({ ok:false, message:'unauthorized' });

    const oldId = Number(req.params.id);
    if (!Number.isFinite(oldId)) return res.status(400).json({ ok:false, message:'bad_id' });

    // 소유권 확인
    const [[own]] = await conn.query(
      'SELECT listing_id FROM listings WHERE listing_id=? AND agent_id=? LIMIT 1',
      [oldId, u.id]
    );
    if (!own) return res.status(404).json({ ok:false, message:'not_found' });

    const b = req.body;

    // 새 레코드에 들어갈 필드 세팅
    const fields = {
      agent_id: u.id,
      title: b.title,
      description: b.description,
      property_type: b.property_type,
      deal_type: b.deal_type,
      sigungu: b.sigungu,
      road_name: b.road_name,
      lot_no: b.lot_no,
      si: b.si, gu: b.gu, dong: b.dong,
      area_m2: b.area_m2 || null,
      gross_area_m2: b.gross_area_m2 || null,
      land_area_m2: b.land_area_m2 || null,
      floor: b.floor || null,
      built_year: b.built_year || null,
      price_sale_10k: b.price_sale_10k || null,
      deposit_10k: b.deposit_10k || null,
      rent_10k: b.rent_10k || null,
      rent_pay_cycle: b.rent_pay_cycle || null,
      status: b.status || 'active',
      full_addr: b.full_addr || null,
      lat: b.lat || null,
      lng: b.lng || null,
      // coord를 lat/lng로 생성한다면 여기서 처리 (예: ST_SRID(POINT(lng,lat),4326))
    };

    // 동적 INSERT
    const cols = Object.keys(fields).filter(k => fields[k] !== undefined);
    const vals = cols.map(k => fields[k]);
    const qs   = cols.map(()=>'?').join(',');

    await conn.beginTransaction();

    const [ins] = await conn.query(
      `INSERT INTO listings (${cols.join(',')}) VALUES (${qs})`,
      vals
    );
    const newId = ins.insertId;

    // 이미지: 새로 업로드된 게 있으면 그걸로, 없으면 기존 이미지 복사(선택)
    if (Array.isArray(req.files) && req.files.length){
      const rows = req.files.map(f => [newId, f.filename]);
      await conn.query(
        'INSERT INTO listing_images (listing_id, image_url) VALUES ?',
        [rows]
      );
    } else {
      // 업로드 없으면 기존 이미지 복사 (원하면 유지)
      const [oldImgs] = await conn.query(
        'SELECT image_url FROM listing_images WHERE listing_id=? ORDER BY image_id',
        [oldId]
      );
      if (oldImgs.length){
        const rows = oldImgs.map(r => [newId, r.image_url]);
        await conn.query(
          'INSERT INTO listing_images (listing_id, image_url) VALUES ?',
          [rows]
        );
      }
    }

    // 기존 매물 제거 방식 결정
    const hard = String(req.query.hard || '').trim() === '1';
    if (hard){
      // 하드 삭제 (주의: FK 이슈 발생 가능)
      await conn.query('DELETE FROM listing_images WHERE listing_id=?', [oldId]);
      await conn.query('DELETE FROM listings WHERE listing_id=?', [oldId]);
    } else {
      // 소프트 삭제: 상태만 변경 → 목록 쿼리에서 status='active'만 노출되게 되어 있어야 함
      await conn.query(
        "UPDATE listings SET status='removed' WHERE listing_id=?",
        [oldId]
      );
    }

    await conn.commit();
    return res.json({ ok:true, new_id: newId });
  } catch (e) {
    try { await conn.rollback(); } catch {}
    console.error(e);
    return res.status(500).json({ ok:false, message:'server_error' });
  } finally {
    conn.release();
  }
});

// 내 매물 CSV 다운로드 (엑셀에서 바로 열림)
app.get('/api/my-listings/export.csv', async (req, res) => {
  try {
    if (!req.session.user || req.session.user.role !== 'agent') {
      return res.status(401).json({ ok:false, message:'unauthorized' });
    }
    const agentId = req.session.user.id;
    const q = (req.query.q || '').trim();

    const where = ['l.agent_id = ?'];
    const params = [agentId];
    if (q) {
      const like = `%${q}%`;
      where.push(`(l.title LIKE ? OR l.description LIKE ? OR l.sigungu LIKE ? OR l.road_name LIKE ? OR l.lot_no LIKE ?)`);
      params.push(like, like, like, like, like);
    }

    const [rows] = await pool.query(
      `
      SELECT
        l.listing_id, l.title, l.description,
        l.property_type, l.deal_type,
        l.sigungu, l.road_name, l.lot_no,
        l.area_m2, l.gross_area_m2, l.land_share_m2, l.land_area_m2,
        l.floor, l.built_year,
        l.price_sale_10k, l.deposit_10k, l.rent_10k, l.rent_pay_cycle, l.rent_annual_10k,
        l.status, l.created_at
      FROM listings l
      WHERE ${where.join(' AND ')}
      ORDER BY l.created_at DESC
      `,
      params
    );

    // CSV 만들기 (엑셀 호환 위해 BOM 추가)
    const header = ['ID','제목','설명','유형','거래','시군구','도로명','지번',
                    '전용(㎡)','연면적(㎡)','대지지분(㎡)','대지면적(㎡)',
                    '층','준공연도','매매가(만원)','보증금(만원)','월세(만원)',
                    '연세(만원)','지불주기','상태','등록일'];
    const esc = v => {
      if (v == null) return '""';
      const s = String(v).replace(/"/g,'""');
      return `"${s}"`;
    };
    const lines = [header.map(esc).join(',')];
    for (const r of rows) {
      lines.push([
        r.listing_id, r.title, r.description, r.property_type, r.deal_type,
        r.sigungu, r.road_name, r.lot_no,
        r.area_m2, r.gross_area_m2, r.land_share_m2, r.land_area_m2,
        r.floor, r.built_year,
        r.price_sale_10k, r.deposit_10k, r.rent_10k,
        r.rent_annual_10k, r.rent_pay_cycle,
        r.status, new Date(r.created_at).toISOString().slice(0,10)
      ].map(esc).join(','));
    }

    const bom = '\uFEFF'; // UTF-8 BOM (엑셀 한글 깨짐 방지)
    const csv = bom + lines.join('\r\n');
    const filename = `my_listings_${new Date().toISOString().slice(0,10)}.csv`;
    res.setHeader('Content-Type','text/csv; charset=utf-8');
    res.setHeader('Content-Disposition', `attachment; filename="${filename}"`);
    res.send(csv);
  } catch (e) {
    console.error('export csv error:', e);
    res.status(500).json({ ok:false });
  }
});


/* ---------- START SERVER ---------- */
const PORT = process.env.PORT || 3000;


/* =========================================================
 * Kakao Map viewport listings API
 * GET /api/map/listings?type=apartment&rect=swLng,swLat,neLng,neLat
 *   &minPrice=&maxPrice=&minArea=&maxArea=&q=&gu=&dong=&page=1
 * Returns: { ok, markers[], list[], total, page, pageSize }
 * ========================================================= */
// /api/map/listings
// ▼ 기존 라우트 통째로 교체
app.get('/api/map/listings', async (req, res) => {
  const listOnly = req.query.list_only === '1';
  const {
    type = 'apartment',
    rect = '',
    page = '1',
    z = '7',
    q = '',
    // --- 선택형 필터(보낸 것만 적용) ---
    deal,                 // l.deal_type
    pay_cycle,            // l.rent_pay_cycle
    minPrice, maxPrice,   // l.price_key_10k
    minArea,  maxArea,    // l.area_key_m2
    si, gu, dong,         // 행정동
    roomsMin, bathsMin,   // 방/욕실 이상
    builtFrom, builtTo,   // 준공년도 범위
    has_parking, allow_pet, is_full_option, has_veranda, has_garden, is_new_build, fee_included,
    debug
  } = req.query;

  try {
    // 1) rect 파싱 (swLng,swLat,neLng,neLat)
    const [swLngStr, swLatStr, neLngStr, neLatStr] = (rect || '').split(',');
    let swLng = parseFloat(swLngStr), swLat = parseFloat(swLatStr);
    let neLng = parseFloat(neLngStr), neLat = parseFloat(neLatStr);

    if (
      !Number.isFinite(swLng) || !Number.isFinite(swLat) ||
      !Number.isFinite(neLng) || !Number.isFinite(neLat)
    ) {
      return res.json({ ok: true, markers: [], list: [], total: 0, page: 1, pageSize: 20 });
    }

    // 2) 뷰포트 정규화
    const west  = Math.min(swLng, neLng);
    const east  = Math.max(swLng, neLng);
    const south = Math.min(swLat, neLat);
    const north = Math.max(swLat, neLat);

    // 3) 페이징/마커 수 제한
    const pageSize = 20;
    const curPage = Math.max(parseInt(page) || 1, 1);
    const offset = (curPage - 1) * pageSize;

    const level = Math.max(parseInt(z) || 7, 1);
    let markerLimit;
    if (level >= 10) markerLimit = 300;
    else if (level >= 8) markerLimit = 1000;
    else if (level >= 6) markerLimit = 3000;
    else markerLimit = 5000;

    // 4) 동적 WHERE/파라미터 (보낸 값만 조건으로 추가)
    const where = [
      "l.status='active'",
      "l.coord IS NOT NULL",
      "ST_Longitude(l.coord) BETWEEN ? AND ?",
      "ST_Latitude(l.coord)  BETWEEN ? AND ?"
    ];
    const params = [west, east, south, north];

    // 타입 파싱 (멀티 지원)
    const rawTypes = String(type||'').split(',').map(s=>s.trim()).filter(Boolean);
    const allow = new Set(['apartment','officetel','rowhouse','detached']);
    const types = rawTypes.filter(t=>allow.has(t));
    if (types.length <= 1) {
      where.unshift("l.property_type = ?");
      params.unshift(types[0] || 'apartment');
    } else {
      where.unshift(`l.property_type IN (${types.map(()=>'?').join(',')})`);
      params.unshift(...types);
    }

    const addStr = (sql, v) => { if (v && String(v).trim() !== '') { where.push(sql); params.push(String(v).trim()); } };
    const addNum = (sql, v) => {
      const n = Number(v);
      if (Number.isFinite(n) && n !== 0) { where.push(sql); params.push(n); }
    };

    // 문자열
    addStr("l.deal_type = ?",       deal);
    addStr("l.rent_pay_cycle = ?",  pay_cycle);
    addStr("l.si = ?",              si);
    addStr("l.gu = ?",              gu);
    addStr("l.dong = ?",            dong);

    // 숫자
    addNum("l.price_key_10k >= ?",  minPrice);
    addNum("l.price_key_10k <= ?",  maxPrice);
    addNum("l.area_key_m2 >= ?",    minArea);
    addNum("l.area_key_m2 <= ?",    maxArea);
    addNum("l.rooms >= ?",          roomsMin);
    addNum("l.bathrooms >= ?",      bathsMin);
    addNum("l.built_year >= ?",     builtFrom);
    addNum("l.built_year <= ?",     builtTo);

    // 체크박스 (체크된 경우만)
    if (has_parking   === '1') where.push("l.has_parking=1");
    if (allow_pet     === '1') where.push("l.allow_pet=1");
    if (is_full_option=== '1') where.push("l.is_full_option=1");
    if (has_veranda   === '1') where.push("l.has_veranda=1");
    if (has_garden    === '1') where.push("l.has_garden=1");
    if (is_new_build  === '1') where.push("l.is_new_build=1");
    if (fee_included  === '1') where.push("l.fee_included=1");

    // 키워드(q): addr_key/title/주소 요소/행정동 결합
    if ((q || '').trim() !== '') {
      const like = `%${String(q).trim().toLowerCase()}%`;
      where.push(`(
        l.addr_key LIKE ? OR l.title LIKE ? OR
        l.sigungu  LIKE ? OR l.road_name LIKE ? OR l.lot_no LIKE ? OR
        CONCAT_WS(' ', l.si, l.gu, l.dong) LIKE ?
      )`);
      params.push(like, like, like, like, like, like);
    }

    // ▶ Fast path: 더 보기 등 리스트만 필요한 경우 (마커/카운트 생략)
    if (listOnly) {
      const limitPlus = pageSize + 1;              // hasMore 판단용으로 1개 더 조회
      const offset    = (page - 1) * pageSize;
      // ⬇️ 기존 list SELECT의 컬럼/WHERE/ORDER BY를 그대로 사용하되 LIMIT만 바꿔주세요.
      const [listPlus] = await pool.query(
       `
        SELECT
           l.listing_id,
           l.title,
           l.deal_type,
           l.price_key_10k,
           ROUND(COALESCE(l.gross_area_m2, l.area_m2, l.land_area_m2),1) AS area_m2,
           l.sigungu, l.road_name, l.lot_no
         FROM listings l
         WHERE ${where.join(' AND ')}
         ORDER BY l.created_at DESC
         LIMIT ? OFFSET ?
       `,
        [...params, limitPlus, offset]
      );
      const hasMore = listPlus.length > pageSize;
       const list    = hasMore ? listPlus.slice(0, pageSize) : listPlus;
       return res.json({ ok: true, list, page: curPage, pageSize, hasMore });
    }

    const whereSql = 'WHERE ' + where.join(' AND ');

    // 5) TOTAL
    const [[cnt]] = await pool.query(
      `SELECT COUNT(*) AS total FROM listings l ${whereSql}`,
      params
    );

    // 6) 마커
    const [markerRows] = await pool.query(
      `SELECT l.listing_id,
              ST_Latitude(l.coord)  AS lat,
              ST_Longitude(l.coord) AS lng,
              l.price_key_10k
         FROM listings l
         ${whereSql}
         ORDER BY l.created_at DESC
         LIMIT ?`,
      [...params, markerLimit]
    );

    // 7) 리스트
    const [listRows] = await pool.query(
      `SELECT l.listing_id, l.title, l.deal_type, l.price_key_10k,
              ROUND(COALESCE(l.gross_area_m2, l.area_m2, l.land_area_m2),1) AS area_m2,
              l.sigungu, l.road_name, l.lot_no,
              ST_Latitude(l.coord)  AS lat,
              ST_Longitude(l.coord) AS lng
         FROM listings l
         ${whereSql}
         ORDER BY l.created_at DESC
         LIMIT ? OFFSET ?`,
      [...params, pageSize, offset]
    );

    // 8) 응답
    res.json({
      ok: true,
      markers: markerRows.map(r => ({
        listing_id: r.listing_id,
        lat: r.lat, lng: r.lng,
        price_key_10k: r.price_key_10k
      })),
      list: listRows,
      total: cnt.total,
      page: curPage,
      pageSize
    });
  } catch (err) {
    if (debug) return res.status(200).json({ ok: false, error: err.message });
    res.status(500).json({ ok: false });
  }
});

// 자유 검색 API: q로 매물 찾고 좌표/요약 반환
app.get('/api/search/listings', async (req, res) => {
  try {
    const type  = (req.query.type || 'apartment').trim();
    const qRaw  = (req.query.q || '').trim();
    const limit = Math.min(200, Math.max(1, parseInt(req.query.limit) || 100));
    if (!qRaw) return res.json({ ok:true, items: [] });

    // addr_key와 맞추기 위해 소문자 + 공백 정규화
    const q = qRaw.toLowerCase().replace(/\s+/g, ' ');
    const like = `%${q}%`;

    const [rows] = await pool.query(`
      SELECT
        l.listing_id, l.title, l.deal_type, l.price_key_10k,
        ROUND(COALESCE(l.gross_area_m2, l.area_m2, l.land_area_m2),1) AS area_m2,
        ST_Latitude(l.coord)  AS lat,
        ST_Longitude(l.coord) AS lng,
        CONCAT_WS(' ', l.sigungu, l.road_name, l.lot_no) AS addr
      FROM listings l
      WHERE l.status='active'
        AND l.property_type = ?
        AND l.coord IS NOT NULL
        AND (
          l.addr_key LIKE ?              -- 정규화된 주소
          OR l.title LIKE ?
          OR l.sigungu LIKE ?
          OR l.road_name LIKE ?
          OR l.lot_no LIKE ?
          OR CONCAT_WS(' ', l.si, l.gu, l.dong) LIKE ?
        )
      ORDER BY l.created_at DESC
      LIMIT ?
    `, [type, like, like, like, like, like, like, limit]);

    res.json({ ok:true, items: rows });
  } catch (e) {
    console.error('search error:', e);
    res.status(500).json({ ok:false });
  }
});

// 상세 조회(+이미지/중개사/즐겨찾기/소유자 플래그)
app.get('/api/listings/:id(\\d+)', async (req, res) => {
  const id = Number(req.params.id);
  const full = req.query.full === '1';
  if (!Number.isFinite(id)) {
    return res.status(400).json({ ok: false, error: 'bad_id' });
  }

  try {
    // 1) listing 본문
    const [[l]] = await pool.query(
      `SELECT *
         FROM listings
        WHERE listing_id = ?`,
      [id]
    );
    if (!l) {
      return res.status(404).json({ ok: false, error: 'not_found' });
    }

    // full=0 이면 listing만 반환
    if (!full) {
      return res.json({ ok: true, listing: l });
    }

    // 2) 이미지 목록
    const [images] = await pool.query(
      `SELECT image_id, image_url
         FROM listing_images
        WHERE listing_id = ?
        ORDER BY image_id`,
      [id]
    );

    // 3) 중개사(네 스키마에 맞춘 컬럼 매핑)
    const [[rawAgent]] = await pool.query(
      `SELECT agent_id, agent_name, nickname, email, profile_url, license_status
         FROM agents
        WHERE agent_id = ?`,
      [l.agent_id]
    );

    const agent = rawAgent
      ? {
          agent_id: rawAgent.agent_id,
          name: rawAgent.agent_name,                 // 표시용 name
          nickname: rawAgent.nickname,
          email: rawAgent.email,
          profile_image_url: rawAgent.profile_url,   // 프론트에서 img.src로 사용
          license_status: rawAgent.license_status,
        }
      : null;

    // 4) 로그인 사용자 기준 부가정보
    const user = req.session?.user || null;
    const isOwner = !!(user && user.role === 'agent' && user.id === l.agent_id);

    

    // 5) 즐겨찾기 여부(테이블이 없다면 try/catch로 안전 처리)
    let isFavorite = false;
    if (user && user.role === 'tenant') {
      const [[fav]] = await pool.query(
        `SELECT 1 FROM favorites WHERE listing_id=? AND user_id=? LIMIT 1`,
        [id, user.id]
      );
      isFavorite = !!fav;
    }

    return res.json({ ok:true, listing:l, images, agent, isOwner, isFavorite });
  } catch (e) {
    console.error(e);
    return res.status(500).json({ ok: false, error: 'server_error' });
  }
});

// 찜 추가
app.post('/api/listings/:id/favorite', async (req, res) => {
  if (!req.session.user || req.session.user.role !== 'tenant') {
    return res.status(401).json({ ok:false, error:'unauthorized' });
  }
  const userId = req.session.user.id;
  const listingId = Number(req.params.id);
  if (!Number.isFinite(listingId)) return res.status(400).json({ ok:false, error:'bad_id' });

  try {
    await pool.query(
      `INSERT IGNORE INTO favorites (user_id, listing_id) VALUES (?, ?)`,
      [userId, listingId]
    );
    return res.json({ ok:true });
  } catch (e) {
    console.error('favorite add error:', e);
    return res.status(500).json({ ok:false, error:'server_error' });
  }
});

// 찜 제거
app.delete('/api/listings/:id/favorite', async (req, res) => {
  if (!req.session.user || req.session.user.role !== 'tenant') {
    return res.status(401).json({ ok:false, error:'unauthorized' });
  }
  const userId = req.session.user.id;
  const listingId = Number(req.params.id);
  if (!Number.isFinite(listingId)) return res.status(400).json({ ok:false, error:'bad_id' });

  try {
    const [r] = await pool.query(
      `DELETE FROM favorites WHERE user_id=? AND listing_id=?`,
      [userId, listingId]
    );
    return res.json({ ok:true, removed: r.affectedRows });
  } catch (e) {
    console.error('favorite remove error:', e);
    return res.status(500).json({ ok:false, error:'server_error' });
  }
});

// 내 찜 목록(간단 버전)
app.get('/api/favorites', async (req, res) => {
  if (!req.session.user) return res.status(401).json({ ok:false, error:'unauthorized' });
  const userId = req.session.user.id;
  try {
    const [rows] = await pool.query(
      `SELECT 
         l.*, 
         f.created_at AS fav_created_at,
         -- 대표 이미지(첫 장) 같이 내려주기
         (SELECT li.image_url 
            FROM listing_images li 
           WHERE li.listing_id = l.listing_id 
           ORDER BY li.image_id 
           LIMIT 1) AS cover_image_url
       FROM favorites f
       JOIN listings l ON l.listing_id = f.listing_id
      WHERE f.user_id = ?
        AND l.status = 'active'
      ORDER BY f.created_at DESC`,
      [userId]
    );
    res.json({ ok:true, listings: rows });
  } catch (e) {
    console.error(e);
    res.status(500).json({ ok:false, error:'server_error' });
  }
});

// 추천: 내 즐겨찾기 주변 1km 매물 (기준 매물 정보 포함)
app.get('/api/recommendations/near-favorites', async (req, res) => {
  try {
    if (!req.session.user || req.session.user.role !== 'tenant') {
      return res.status(401).json({ ok:false, error:'unauthorized' });
    }
    const userId = req.session.user.id;
    const basisId = Number(req.query.basis); // 선택한 기준 listing_id (없으면 전체)

    if (basisId) {
    const [rows] = await pool.query(
      `
      SELECT
        l.listing_id, l.title, l.deal_type,
        l.price_sale_10k, l.deposit_10k, l.rent_10k, l.rent_annual_10k, l.rent_effective_monthly_10k,

        l.price_key_10k,
        ROUND(COALESCE(l.gross_area_m2, l.area_m2, l.land_area_m2),1) AS area_m2,
        l.sigungu, l.road_name, l.lot_no,
        ST_Latitude(l.coord)  AS lat,
        ST_Longitude(l.coord) AS lng,
        ST_Distance_Sphere(l.coord, fl.coord) AS basis_dist_m,
        (SELECT li.image_url FROM listing_images li
          WHERE li.listing_id=l.listing_id ORDER BY li.image_id LIMIT 1) AS cover_image_url,
        fl.listing_id AS basis_listing_id,
        fl.title      AS basis_title,
        (SELECT li2.image_url FROM listing_images li2
          WHERE li2.listing_id=fl.listing_id ORDER BY li2.image_id LIMIT 1) AS basis_cover_image_url
      FROM listings l
      JOIN listings fl ON fl.listing_id=?  -- 기준 매물
      WHERE l.status='active' AND l.coord IS NOT NULL
        AND l.listing_id <> fl.listing_id
        AND ST_Distance_Sphere(l.coord, fl.coord) <= 1000
        AND NOT EXISTS (
          SELECT 1 FROM favorites f2
          WHERE f2.user_id=? AND f2.listing_id=l.listing_id
        )
      ORDER BY basis_dist_m ASC, l.created_at DESC
      LIMIT 24
      `,
      [basisId, userId]
    );
    return res.json({ ok:true, items: rows, basis: 'single', basisId });
  }

    // basisId가 없는 "전체" 기준
    const uid = req.session.user.id;
    const [rows] = await pool.query(
      `
      SELECT *
      FROM (
        SELECT
          l.listing_id, l.title, l.deal_type, l.property_type, l.addr_key,
          l.price_sale_10k, l.deposit_10k, l.rent_10k, l.rent_annual_10k, l.rent_effective_monthly_10k,
          l.price_key_10k,
          ROUND(COALESCE(l.gross_area_m2, l.area_m2, l.land_area_m2),1) AS area_m2,
          l.sigungu, l.road_name, l.lot_no,
          ST_Latitude(l.coord)  AS lat,
          ST_Longitude(l.coord) AS lng,
          l.created_at,

          /* 내 즐겨찾기 중 l과 가장 가까운 기준 */
          ( SELECT fl2.listing_id
              FROM favorites f2 JOIN listings fl2 ON fl2.listing_id=f2.listing_id
            WHERE f2.user_id=? AND fl2.coord IS NOT NULL
            ORDER BY ST_Distance_Sphere(l.coord, fl2.coord) ASC
            LIMIT 1 ) AS basis_listing_id,

          ( SELECT fl2.title
              FROM favorites f2 JOIN listings fl2 ON fl2.listing_id=f2.listing_id
            WHERE f2.user_id=? AND fl2.coord IS NOT NULL
            ORDER BY ST_Distance_Sphere(l.coord, fl2.coord) ASC
            LIMIT 1 ) AS basis_title,

          ( SELECT ST_Distance_Sphere(l.coord, fl2.coord)
              FROM favorites f2 JOIN listings fl2 ON fl2.listing_id=f2.listing_id
            WHERE f2.user_id=? AND fl2.coord IS NOT NULL
            ORDER BY ST_Distance_Sphere(l.coord, fl2.coord) ASC
            LIMIT 1 ) AS basis_dist_m,

          /* 대표 이미지들 */
          (SELECT image_url FROM listing_images WHERE listing_id=l.listing_id ORDER BY image_id LIMIT 1) AS cover_image_url,
          (SELECT image_url FROM listing_images WHERE listing_id=
              ( SELECT fl2.listing_id
                  FROM favorites f2 JOIN listings fl2 ON fl2.listing_id=f2.listing_id
                WHERE f2.user_id=? AND fl2.coord IS NOT NULL
                ORDER BY ST_Distance_Sphere(l.coord, fl2.coord) ASC
                LIMIT 1 )
            ORDER BY image_id LIMIT 1) AS basis_cover_image_url,

          /* 중복 제거/상한 랭크(윈도 함수) */
          ROW_NUMBER() OVER (
            PARTITION BY
              /* 기준별 + 같은 건물/유형/거래유형 */
              ( SELECT fl2.listing_id FROM favorites f2 JOIN listings fl2 ON fl2.listing_id=f2.listing_id
                WHERE f2.user_id=? AND fl2.coord IS NOT NULL
                ORDER BY ST_Distance_Sphere(l.coord, fl2.coord) ASC LIMIT 1 ),
              l.addr_key, l.property_type, l.deal_type
            ORDER BY
              /* 기준에 더 가까운 순, 최신순 */
              ( SELECT ST_Distance_Sphere(l.coord, fl2.coord)
                  FROM favorites f2 JOIN listings fl2 ON fl2.listing_id=f2.listing_id
                WHERE f2.user_id=? AND fl2.coord IS NOT NULL
                ORDER BY ST_Distance_Sphere(l.coord, fl2.coord) ASC LIMIT 1 ) ASC,
              l.created_at DESC, l.listing_id DESC
          ) AS dup_rank,

          ROW_NUMBER() OVER (
            PARTITION BY
              ( SELECT fl2.listing_id FROM favorites f2 JOIN listings fl2 ON fl2.listing_id=f2.listing_id
                WHERE f2.user_id=? AND fl2.coord IS NOT NULL
                ORDER BY ST_Distance_Sphere(l.coord, fl2.coord) ASC LIMIT 1 )
            ORDER BY
              ( SELECT ST_Distance_Sphere(l.coord, fl2.coord)
                  FROM favorites f2 JOIN listings fl2 ON fl2.listing_id=f2.listing_id
                WHERE f2.user_id=? AND fl2.coord IS NOT NULL
                ORDER BY ST_Distance_Sphere(l.coord, fl2.coord) ASC LIMIT 1 ) ASC,
              l.created_at DESC, l.listing_id DESC
          ) AS per_basis_rank
        FROM listings l
        WHERE l.status='active'
          AND l.coord IS NOT NULL
          /* 내 즐겨찾기 중 1km 이내인 후보만 */
          AND EXISTS (
            SELECT 1
              FROM favorites f JOIN listings fl ON fl.listing_id=f.listing_id
            WHERE f.user_id=? AND fl.coord IS NOT NULL
              AND ST_Distance_Sphere(l.coord, fl.coord) <= 1000
          )
          /* 내가 이미 찜한 매물은 제외 */
          AND NOT EXISTS (
            SELECT 1 FROM favorites f3
            WHERE f3.user_id=? AND f3.listing_id=l.listing_id
          )
      ) ranked
      WHERE dup_rank=1      /* 같은 건물/유형/거래유형 중복 제거 */
        AND per_basis_rank<=6 /* 기준별 상한 */
      ORDER BY basis_dist_m ASC, created_at DESC
      LIMIT 24
      `,
      [uid, uid, uid, uid, uid, uid, uid, uid, uid, uid] // 자리수 맞춰서 동일 uid 바인딩
    );


    return res.json({ ok:true, items: rows, basis: 'near_favorites' });
  } catch (e) {
    console.error('recommendations error:', e);
    return res.status(500).json({ ok:false, error:'server_error' });
  }
});

// 내 즐겨찾기 타이틀 목록 (버튼 라벨용)
app.get('/api/favorites/titles', async (req, res) => {
  if (!req.session.user || req.session.user.role !== 'tenant') {
    return res.status(401).json({ ok:false, error:'unauthorized' });
  }
  const userId = req.session.user.id;
  const [rows] = await pool.query(
    `SELECT f.listing_id, l.title
       FROM favorites f
       JOIN listings l ON l.listing_id = f.listing_id
      WHERE f.user_id=?
      ORDER BY f.created_at DESC`,
    [userId]
  );
  res.json({ ok:true, items: rows });
});


/* -------------------- CHAT API -------------------- */

// 방 생성/획득: (세입자 전용) listing_id로 해당 매물의 agent_id를 찾아서 (user_id, agent_id, listing_id) 조합의 방을 리턴/생성
app.post('/api/chat/room', async (req, res) => {
  try {
    if (!req.session.user || req.session.user.role !== 'tenant') {
      return res.status(401).json({ ok:false, error:'unauthorized' });
    }
    const userId = req.session.user.id;
    const { listing_id } = req.body;
    if (!listing_id) return res.status(400).json({ ok:false, error:'listing_id_required' });

    // 매물의 agent_id 조회
    const [[L]] = await pool.query(
      "SELECT listing_id, agent_id, title FROM listings WHERE listing_id=? LIMIT 1",
      [listing_id]
    );
    if (!L) return res.status(404).json({ ok:false, error:'listing_not_found' });

    // 동일 agent/user/listing 조합 방이 있으면 재사용
    const [[R]] = await pool.query(
      "SELECT room_id FROM chat_rooms WHERE agent_id=? AND user_id=? AND listing_id <=> ? LIMIT 1",
      [L.agent_id, userId, listing_id]
    );
    let roomId = R?.room_id;

    if (!roomId) {
      const [ins] = await pool.query(
        "INSERT INTO chat_rooms (agent_id, user_id, listing_id) VALUES (?, ?, ?)",
        [L.agent_id, userId, listing_id]
      );
      roomId = ins.insertId;

      // 시스템 안내 메시지(처음 방 생성 시)
      await pool.query(
        "INSERT INTO chat_messages (room_id, sender_type, message_text) VALUES (?, 'user', ?)",
        [roomId, `안녕하세요! '${L.title || '매물'}' 문의드립니다.`]
      );
    }

    // 방 정보 + 매물 일부 정보 동봉
    return res.json({
      ok:true,
      room:{ room_id: roomId, agent_id: L.agent_id, user_id: userId, listing_id },
    });
  } catch (e) {
    console.error('chat room create error:', e);
    res.status(500).json({ ok:false, error:'server_error' });
  }
});

// 내 방 목록: (세입자/중개사 공용) 마지막 메시지와 함께, listing 정보 타이틀 같이 반환
app.get('/api/chat/rooms', async (req, res) => {
  try {
    if (!req.session.user) return res.status(401).json({ ok:false, error:'unauthorized' });
    const me = req.session.user;

    let rows = [];
    if (me.role === 'tenant') {
      [rows] = await pool.query(
        `SELECT r.room_id, r.agent_id, r.user_id, r.listing_id,
                l.title AS listing_title,
                (SELECT message_text FROM chat_messages m WHERE m.room_id=r.room_id ORDER BY m.message_id DESC LIMIT 1) AS last_text,
                (SELECT sent_at FROM chat_messages m WHERE m.room_id=r.room_id ORDER BY m.message_id DESC LIMIT 1) AS last_time
           FROM chat_rooms r
           LEFT JOIN listings l ON l.listing_id=r.listing_id
          WHERE r.user_id=? 
          ORDER BY (last_time IS NULL), last_time DESC`,
        [me.id]
      );
    } else if (me.role === 'agent') {
      [rows] = await pool.query(
        `SELECT r.room_id, r.agent_id, r.user_id, r.listing_id,
                l.title AS listing_title,
                (SELECT message_text FROM chat_messages m WHERE m.room_id=r.room_id ORDER BY m.message_id DESC LIMIT 1) AS last_text,
                (SELECT sent_at FROM chat_messages m WHERE m.room_id=r.room_id ORDER BY m.message_id DESC LIMIT 1) AS last_time,
                u.user_name AS user_name, u.nickname AS user_nick
           FROM chat_rooms r
           LEFT JOIN listings l ON l.listing_id=r.listing_id
           LEFT JOIN users u ON u.user_id=r.user_id
          WHERE r.agent_id=?
          ORDER BY (last_time IS NULL), last_time DESC`,
        [me.id]
      );
    } else {
      return res.status(403).json({ ok:false, error:'forbidden' });
    }

    return res.json({ ok:true, items: rows || [] });
  } catch (e) {
    console.error('chat rooms list error:', e);
    res.status(500).json({ ok:false });
  }
});

// 메시지 전송
app.post('/api/chat/messages', async (req, res) => {
  try {
    if (!req.session.user) return res.status(401).json({ ok:false });
    const { room_id, text } = req.body;
    if (!room_id || !text || !text.trim()) return res.status(400).json({ ok:false, error:'bad_params' });

    // 방 권한 체크
    const [[r]] = await pool.query("SELECT agent_id, user_id FROM chat_rooms WHERE room_id=? LIMIT 1", [room_id]);
    if (!r) return res.status(404).json({ ok:false, error:'room_not_found' });

    let sender_type = null;
    if (req.session.user.role === 'tenant' && req.session.user.id === r.user_id) sender_type = 'user';
    if (req.session.user.role === 'agent'  && req.session.user.id === r.agent_id) sender_type = 'agent';
    if (!sender_type) return res.status(403).json({ ok:false, error:'no_access' });

    const [ins] = await pool.query(
      "INSERT INTO chat_messages (room_id, sender_type, message_text) VALUES (?, ?, ?)",
      [room_id, sender_type, text.trim()]
    );
    return res.json({ ok:true, id: ins.insertId });
  } catch (e) {
    console.error('chat send error:', e);
    res.status(500).json({ ok:false });
  }
});

// 메시지 조회(폴링): since_id 이후 것만
app.get('/api/chat/messages', async (req, res) => {
  try {
    if (!req.session.user) return res.status(401).json({ ok:false });
    const room_id = Number(req.query.room_id);
    const since_id = Number(req.query.since_id || 0);
    if (!Number.isFinite(room_id)) return res.status(400).json({ ok:false });

    // 방 권한 체크
    const [[r]] = await pool.query("SELECT agent_id, user_id FROM chat_rooms WHERE room_id=? LIMIT 1", [room_id]);
    if (!r) return res.status(404).json({ ok:false, error:'room_not_found' });

    const me = req.session.user;
    const allowed =
      (me.role === 'tenant' && me.id === r.user_id) ||
      (me.role === 'agent'  && me.id === r.agent_id);
    if (!allowed) return res.status(403).json({ ok:false });

    const [rows] = await pool.query(
      "SELECT message_id, sender_type, message_text, sent_at FROM chat_messages WHERE room_id=? AND message_id>? ORDER BY message_id ASC",
      [room_id, since_id]
    );
    return res.json({ ok:true, items: rows });
  } catch (e) {
    console.error('chat fetch error:', e);
    res.status(500).json({ ok:false });
  }
});

// 방 메타: listing 정보(타이틀/주소/가격/이미지) 반환
app.get('/api/chat/room-meta', async (req, res) => {
  try {
    if (!req.session.user) return res.status(401).json({ ok:false, error:'unauthorized' });
    const room_id = Number(req.query.room_id);
    if (!Number.isFinite(room_id)) return res.status(400).json({ ok:false, error:'bad_room_id' });

    const [[r]] = await pool.query(
      "SELECT room_id, agent_id, user_id, listing_id FROM chat_rooms WHERE room_id=?",
      [room_id]
    );
    if (!r) return res.status(404).json({ ok:false, error:'room_not_found' });

    const me = req.session.user;
    const allowed =
      (me.role === 'tenant' && me.id === r.user_id) ||
      (me.role === 'agent'  && me.id === r.agent_id);
    if (!allowed) return res.status(403).json({ ok:false, error:'forbidden' });

    if (!r.listing_id) {
      return res.json({ ok:true, meta: null }); // 예전 방은 listing_id가 없을 수 있음
    }

    const [[L]] = await pool.query(
      `SELECT listing_id, title, property_type, deal_type,
              CONCAT_WS(' ', si, gu, dong, road_name, lot_no) AS addr,
              price_sale_10k, deposit_10k, rent_10k
         FROM listings
        WHERE listing_id=? LIMIT 1`,
      [r.listing_id]
    );

    const [[img]] = await pool.query(
      "SELECT image_url FROM listing_images WHERE listing_id=? ORDER BY image_id ASC LIMIT 1",
      [r.listing_id]
    );

    return res.json({
      ok:true,
      meta: {
        listing_id: L?.listing_id ?? r.listing_id,
        title: L?.title ?? '',
        addr: L?.addr ?? '',
        property_type: L?.property_type ?? null,
        deal_type: L?.deal_type ?? null,
        price_sale_10k: L?.price_sale_10k ?? null,
        deposit_10k: L?.deposit_10k ?? null,
        rent_10k: L?.rent_10k ?? null,
        image_url: img?.image_url ?? null
      }
    });
  } catch (e) {
    console.error('room-meta error:', e);
    res.status(500).json({ ok:false, error:'server_error' });
  }
});

// 내 프로필(확장) 읽기
app.get('/api/profile/me', async (req, res) => {
  if (!req.session.user) return res.status(401).json({ ok:false });
  const me = req.session.user;

  if (me.role === 'tenant') {
    const [[u]] = await pool.query(
      `SELECT user_id, user_name, email, nickname, profile_url,
              phone, contact_kakao, contact_hours, bio
         FROM users WHERE user_id=? LIMIT 1`, [me.id]);
    return res.json({ ok:true, role:'tenant', profile:u || null });
  }
  if (me.role === 'agent') {
    const [[a]] = await pool.query(
      `SELECT agent_id AS user_id, agent_name AS user_name, email, nickname, profile_url,
              phone, contact_kakao, contact_hours, bio
         FROM agents WHERE agent_id=? LIMIT 1`, [me.id]);
    return res.json({ ok:true, role:'agent', profile:a || null });
  }
  res.json({ ok:true, role:me.role, profile:null });
});


// 연락처 & 소개 저장
app.post('/api/profile/contact', async (req, res) => {
  try{
    if(!req.session.user) return res.status(401).json({ok:false});
    const me = req.session.user;
    const { phone, contact_kakao, contact_hours, bio } = req.body || {};
    if (me.role === 'tenant') {
      await pool.query(
        `UPDATE users 
            SET phone=?, contact_kakao=?, contact_hours=?, bio=? 
          WHERE user_id=?`,
        [phone||null, contact_kakao||null, contact_hours||null, bio||null, me.id]
      );
    } else if (me.role === 'agent') {
      await pool.query(
        `UPDATE agents 
            SET phone=?, contact_kakao=?, contact_hours=?, bio=? 
          WHERE agent_id=?`,
        [phone||null, contact_kakao||null, contact_hours||null, bio||null, me.id]
      );
    } else {
      return res.status(403).json({ok:false});
    }
    res.json({ ok:true });
  }catch(e){ console.error(e); res.status(500).json({ok:false}); }
});

// 방의 상대 프로필 (중개사면 세입자 정보, 세입자면 중개사 정보)
app.get('/api/chat/room-partner', async (req, res) => {
  try{
    if(!req.session.user) return res.status(401).json({ok:false});
    const me = req.session.user;
    const room_id = Number(req.query.room_id);
    if(!Number.isFinite(room_id)) return res.status(400).json({ok:false, error:'bad_room_id'});

    const [[r]] = await pool.query(
      "SELECT room_id, agent_id, user_id FROM chat_rooms WHERE room_id=?",
      [room_id]
    );
    if(!r) return res.status(404).json({ok:false, error:'room_not_found'});
    const allowed = (me.role==='tenant' && me.id===r.user_id) || (me.role==='agent' && me.id===r.agent_id);
    if(!allowed) return res.status(403).json({ok:false});

    if (me.role === 'agent'){
      const [[u]] = await pool.query(
        `SELECT user_id, user_name, nickname, email, profile_url, 
                phone, contact_kakao, contact_hours, bio
           FROM users WHERE user_id=?`, [r.user_id]);
      return res.json({ ok:true, partner: u, partner_role:'tenant' });
    } else {
      const [[a]] = await pool.query(
        `SELECT agent_id AS user_id, agent_name AS user_name, nickname, email, profile_url, 
                phone, contact_kakao, contact_hours, bio
           FROM agents WHERE agent_id=?`, [r.agent_id]);
      return res.json({ ok:true, partner: a, partner_role:'agent' });
    }
  }catch(e){ console.error(e); res.status(500).json({ok:false}); }
});


// ===== 공지: 목록 (모두 열람) =====
app.get('/api/notices', async (req, res) => {
  try {
    const limit  = Math.min(100, Math.max(1, parseInt(req.query.limit) || 20));
    const offset = Math.max(0, parseInt(req.query.offset) || 0);
    const [rows] = await pool.query(
      `SELECT notice_id, title, created_at, updated_at
         FROM notices
        WHERE is_published=1
        ORDER BY created_at DESC
        LIMIT ? OFFSET ?`,
      [limit, offset]
    );
    res.json({ ok:true, items: rows });
  } catch (e) {
    console.error('list notices error:', e);
    res.status(500).json({ ok:false });
  }
});

// ===== 공지: 단건 (모두 열람) =====
app.get('/api/notices/:id', async (req, res) => {
  try {
    const id = Number(req.params.id);
    if (!Number.isFinite(id)) return res.status(400).json({ ok:false, error:'bad_id' });
    const [[row]] = await pool.query(
      `SELECT notice_id, title, content, created_at, updated_at
         FROM notices
        WHERE notice_id=? AND is_published=1
        LIMIT 1`,
      [id]
    );
    if (!row) return res.status(404).json({ ok:false, error:'not_found' });
    res.json({ ok:true, notice: row });
  } catch (e) {
    console.error('GET /api/notices/:id', e);
    res.status(500).json({ ok:false, error:'server_error' });
  }
});

// ===== 공지: 작성 (관리자만) =====
app.post('/api/notices', async (req, res) => {
  try {
    if (!req.session.user || req.session.user.role !== 'admin') {
      return res.status(403).json({ ok:false, message: 'forbidden' });
    }
    const { title = '', content = '' } = req.body || {};
    if (!title.trim() || !content.trim()) {
      return res.status(400).json({ ok:false, message: 'title/content required' });
    }
    const authorId = req.session.user.id || null;
    const [r] = await pool.query(
      `INSERT INTO notices (title, content, author_admin_id, is_published)
       VALUES (?, ?, ?, 1)`,
      [title.trim(), content, authorId]
    );
    res.json({ ok:true, id:r.insertId });
  } catch (e) {
    console.error('create notice error:', e);
    res.status(500).json({ ok:false });
  }
});

// 최근 문의(에이전트 전용): 가장 최근 채팅방 1건
app.get('/api/agents/me/recent-chat', async (req, res) => {
  try {
    const u = req.session?.user;
    if (!u || u.role !== 'agent') {
      return res.status(403).json({ ok:false, error:'forbidden' });
    }

    // chat_rooms(room_id, agent_id, user_id, created_at) 기준
    // users에서 표시용 이름 가져오기
    const [[row]] = await pool.query(
      `SELECT r.room_id,
              r.created_at,
              u.user_id,
              COALESCE(u.nickname, u.user_name, CONCAT('사용자 ', u.user_id)) AS user_name
         FROM chat_rooms r
         JOIN users u ON u.user_id = r.user_id
        WHERE r.agent_id = ?
        ORDER BY r.created_at DESC
        LIMIT 1`,
      [u.id]
    );

    if (!row) return res.json({ ok:true, room:null }); // 채팅 없음
    res.json({ ok:true, room: row });
  } catch (e) {
    console.error('GET /api/agents/me/recent-chat', e);
    res.status(500).json({ ok:false, error:'server_error' });
  }
});

// 가이드 HWP 다운로드
app.get('/api/guide', (req, res) => {
  const file = path.join(__dirname, 'public', 'docs', '홈스팟_가이드.hwpx');
  res.download(file, '홈스팟_가이드.hwpx', (err) => {
    if (err) {
      console.error('guide download error:', err);
      if (!res.headersSent) res.status(404).send('file not found');
    }
  });
});

// === Tenant 메인 전용: 경량 검색 API (전체매물 포함) ===
// GET /api/listings/search?type=all&q=마포&page=1&pageSize=12
app.get('/api/listings/search', async (req, res) => {
  try {
    const rawType  = (req.query.type || 'all').trim().toLowerCase(); // apartment/officetel/rowhouse/detached/all
    const q        = (req.query.q || '').trim();
    const page     = Math.max(1, parseInt(req.query.page) || 1);
    const pageSize = Math.min(50, Math.max(1, parseInt(req.query.pageSize) || 12));

    const where = [`l.status='active'`];
    const params = [];

    if (rawType !== 'all') {
      where.push(`l.property_type = ?`);
      params.push(rawType);
    }
    if (q) {
      const like = `%${q}%`;
      where.push(`(l.title LIKE ? OR l.description LIKE ? OR l.sigungu LIKE ? OR l.road_name LIKE ? OR l.lot_no LIKE ?)`);
      params.push(like, like, like, like, like);
    }

    const whereSql = where.length ? `WHERE ${where.join(' AND ')}` : '';
    const [[{ total }]] = await pool.query(
      `SELECT COUNT(*) AS total FROM listings l ${whereSql}`,
      params
    );

    const offset = (page - 1) * pageSize;
    const [rows] = await pool.query(
      `
      SELECT
        l.listing_id, l.title, l.description,
        l.property_type, l.deal_type,
        l.price_sale_10k, l.deposit_10k, l.rent_10k, l.rent_pay_cycle, l.rent_annual_10k,
        l.sigungu, l.road_name, l.lot_no,
        l.created_at,
        (SELECT li.image_url FROM listing_images li
          WHERE li.listing_id = l.listing_id ORDER BY li.image_id ASC LIMIT 1) AS cover_image_url
      FROM listings l
      ${whereSql}
      ORDER BY l.created_at DESC
      LIMIT ? OFFSET ?
      `,
      [...params, pageSize, offset]
    );

    res.json({ ok:true, items: rows, total, page, pageSize });
  } catch (e) {
    console.error('listings/search error:', e);
    res.status(500).json({ ok:false });
  }
});


app.listen(PORT, () => console.log("Server running at http://localhost:" + PORT));

/* ---------- SES SDK MAILER ---------- */
async function sendEmail({ to, subject, text, html }) {
  const input = {
    FromEmailAddress: process.env.SES_FROM, // SES에서 검증된 이메일
    Destination: { ToAddresses: Array.isArray(to) ? to : [to] },
    Content: {
      Simple: {
        Subject: { Data: subject, Charset: 'UTF-8' },
        Body: {
          Text: text ? { Data: text, Charset: 'UTF-8' } : undefined,
          Html: html ? { Data: html, Charset: 'UTF-8' } : undefined
        }
      }
    }
    // 필요 시 ConfigurationSetName 추가 가능
  };
  await ses.send(new SendEmailCommand(input));
}

