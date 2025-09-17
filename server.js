// server.js — Ollama 연동 + SSE(EventSource) + GPU 옵션(num_gpu)
// Node 18+ (fetch 내장). package.json에 "type": "module" 가정.

import express from 'express';
import cors from 'cors';

// ===================== 기본 설정 =====================
const app = express();
app.use(express.json());

// CORS (프런트가 http://localhost:3000 이라면 아래 origin 그대로)
app.use(cors({
  origin: 'http://localhost:3000',
  methods: ['GET', 'POST', 'OPTIONS'],
  allowedHeaders: ['Content-Type'],
  credentials: false,
}));

// 모든 요청 로깅 (요청이 안 들어오는지 트레이스)
app.use((req, _res, next) => {
  console.log(`[REQ] ${req.method} ${req.url}`);
  next();
});

// 환경변수
const OLLAMA = process.env.OLLAMA_HOST || 'http://localhost:11434';
const MODEL  = process.env.MODEL || 'my-cs-bot-3b';
// GPU 개수. CPU-only면 0으로 두면 됨(무시됨). 기본 1.
const OLLAMA_NUM_GPU = Number(process.env.OLLAMA_NUM_GPU || process.env.NUM_GPU || 1) || 0;

// 대화 세션 저장(최근 20턴 유지)
const sessions = new Map();

// 오프토픽(코드/스크립트) 간단 필터 — 필요 없으면 항상 false 반환하게 바꿔도 됨.
function isOffTopic(text = '') {
  const k = [
    'python','자바','javascript','코드','코딩','스크립트',
    '알고리즘','print(','import ','def ','class ',
    'console.log','function','```','<script','select '
  ];
  const t = (text || '').toLowerCase();
  return k.some(w => t.includes(w));
}
const refusalMsg =
  '이 봇은 전·월세/연세 등 임대차 안전 정보만 안내합니다. 전세보증보험, 등기부 확인, 깡통전세 판단, 전입/확정일자, 연세/월세 비교 중 무엇을 도와드릴까요?';

// fetch 타임아웃 래퍼
async function fetchWithTimeout(url, opts = {}, ms = 120000) {
  const controller = new AbortController();
  const id = setTimeout(() => controller.abort(), ms);
  try {
    const r = await fetch(url, { ...opts, signal: controller.signal });
    return r;
  } finally {
    clearTimeout(id);
  }
}

// ===================== 헬스 체크 =====================
app.get('/health', (_req, res) => {
  res.json({ ok: true, model: MODEL, ollama: OLLAMA, num_gpu: OLLAMA_NUM_GPU });
});

// ===================== 비스트리밍 (확인/폴백용) =====================
app.post('/api/chat', async (req, res) => {
  try {
    const { sessionId = 'default', user } = req.body || {};
    if (!user || typeof user !== 'string') return res.status(400).json({ error: 'user 필요' });
    if (isOffTopic(user)) return res.json({ content: refusalMsg });

    const history = sessions.get(sessionId) || [];
    history.push({ role: 'user', content: user });

    const r = await fetchWithTimeout(`${OLLAMA}/api/chat`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({
        model: MODEL,
        stream: false,
        messages: history,
        options: { num_gpu: OLLAMA_NUM_GPU },
      }),
    });

    if (!r.ok) {
      const text = await r.text().catch(()=>'');
      throw new Error(`Ollama ${r.status} ${r.statusText} ${text}`);
    }
    const data = await r.json().catch(()=> ({}));
    const content = data?.message?.content ?? '';
    history.push({ role: 'assistant', content });
    sessions.set(sessionId, history.slice(-20));
    res.json({ content });
  } catch (e) {
    console.error('OLLAMA ERROR:', e);
    res.status(502).json({ error: 'ollama_unreachable', detail: String(e) });
  }
});

// ===================== SSE 핑(파이프라인 테스트) =====================
app.get('/api/chat/ping-sse', (req, res) => {
  // CORS + SSE 헤더
  res.setHeader('Access-Control-Allow-Origin', 'http://localhost:3000');
  res.setHeader('Access-Control-Allow-Credentials', 'false');
  res.setHeader('Content-Type', 'text/event-stream; charset=utf-8');
  res.setHeader('Cache-Control', 'no-cache');
  res.setHeader('Connection', 'keep-alive');

  console.log('[ping-sse] start');
  res.write('data: 핑1\n\n');
  setTimeout(() => res.write('data: 핑2\n\n'), 300);
  setTimeout(() => {
    res.write('event: done\ndata: ok\n\n');
    res.end();
    console.log('[ping-sse] end');
  }, 600);
});

// ===================== SSE 스트리밍(GET, EventSource 전용) =====================
app.get('/api/chat/stream-es', async (req, res) => {
  console.log('[stream-es] q =', req.query);
  const sessionId = req.query.sessionId || 'default';
  const user = req.query.user || '';
  if (!user || typeof user !== 'string') { res.status(400).end(); return; }
  if (isOffTopic(user)) {
    res.setHeader('Access-Control-Allow-Origin', 'http://localhost:3000');
    res.setHeader('Access-Control-Allow-Credentials', 'false');
    res.setHeader('Content-Type', 'text/event-stream; charset=utf-8');
    res.setHeader('Cache-Control', 'no-cache');
    res.setHeader('Connection', 'keep-alive');
    res.write(`data: ${refusalMsg}\n\n`);
    res.write('event: done\ndata: ok\n\n');
    return res.end();
  }

  const history = sessions.get(sessionId) || [];
  history.push({ role: 'user', content: user });

  // SSE 헤더
  res.setHeader('Access-Control-Allow-Origin', 'http://localhost:3000');
  res.setHeader('Access-Control-Allow-Credentials', 'false');
  res.setHeader('Content-Type', 'text/event-stream; charset=utf-8');
  res.setHeader('Cache-Control', 'no-cache');
  res.setHeader('Connection', 'keep-alive');

  try {
    console.log('[stream-es] call ollama:', OLLAMA, 'model:', MODEL, 'num_gpu:', OLLAMA_NUM_GPU);
    const r = await fetchWithTimeout(`${OLLAMA}/api/chat`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({
        model: MODEL,
        stream: true,
        messages: history,
        options: { num_gpu: OLLAMA_NUM_GPU },
      }),
    }, 120000);

    if (!r.ok || !r.body) {
      const text = await r.text().catch(()=> '');
      throw new Error(`Ollama stream ${r.status} ${r.statusText} ${text}`);
    }

    const reader = r.body.getReader();
    const decoder = new TextDecoder();
    let buf = '', full = '';
    let firstSent = false;

    while (true) {
      const { value, done } = await reader.read();
      if (done) break;
      buf += decoder.decode(value, { stream: true });

      let idx;
      while ((idx = buf.indexOf('\n')) >= 0) {
        const line = buf.slice(0, idx).trim();
        buf = buf.slice(idx + 1);
        if (!line) continue;

        try {
          const obj = JSON.parse(line); // Ollama는 NDJSON
          const delta = obj?.message?.content || obj?.response || '';
          if (delta) {
            full += delta;
            if (!firstSent) { firstSent = true; console.log('[stream-es] first delta len', delta.length); }
            // 줄바꿈 이스케이프해서 보냄 (클라에서 \n 복원)
            res.write(`data: ${delta.replace(/\n/g, '\\n')}\n\n`);
          }
          if (obj?.done) {
            history.push({ role: 'assistant', content: full });
            sessions.set(sessionId, history.slice(-20));
            res.write('event: done\ndata: ok\n\n');
            return res.end();
          }
        } catch {
          // JSON 파싱 안 되는 중간조각은 무시
        }
      }
    }
    // 혹시 여기까지 왔는데 종료 신호가 없으면 강제 종료
    res.write('event: done\ndata: ok\n\n');
    res.end();
  } catch (err) {
    console.error('OLLAMA STREAM ES ERROR:', err);
    res.write(`event: error\ndata: ${String(err)}\n\n`);
    res.write('event: done\ndata: fail\n\n');
    res.end();
  }
});

// ===================== 워밍업 =====================
(async () => {
  try {
    await fetch(`${OLLAMA}/api/chat`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({
        model: MODEL,
        stream: false,
        messages: [{ role: 'user', content: 'warm up' }],
        options: { num_gpu: OLLAMA_NUM_GPU },
      }),
    });
    console.log('Warmup ok (num_gpu:', OLLAMA_NUM_GPU, ')');
  } catch (e) {
    console.warn('Warmup failed:', e?.message || e);
  }
})();

// ===================== 서버 시작 =====================
app.listen(4000, () => {
  console.log('API on http://localhost:4000 (model:', MODEL, ', ollama:', OLLAMA, ', num_gpu:', OLLAMA_NUM_GPU, ')');
});
