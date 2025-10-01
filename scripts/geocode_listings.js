// scripts/geocode_listings.js
import 'dotenv/config';
import axios from 'axios';
import mysql from 'mysql2/promise';

const {
  DB_HOST = '127.0.0.1',
  DB_PORT = '3306',
  DB_USER = 'appuser',
  DB_PASS = '',
  DB_NAME = 'homespot',
  KAKAO_REST_KEY,
} = process.env;

if (!KAKAO_REST_KEY) {
  console.error('❌ KAKAO_REST_KEY (REST API 키)가 필요합니다.');
  process.exit(1);
}

const pool = await mysql.createPool({
  host: DB_HOST,
  port: Number(DB_PORT),
  user: DB_USER,
  password: DB_PASS,
  database: DB_NAME,
  waitForConnections: true,
  connectionLimit: 4,
});

// --- (선택) full_addr 컬럼 없으면 추가 (이미 있으면 무시) ---
try {
  await pool.query(`ALTER TABLE listings ADD COLUMN full_addr VARCHAR(300) NULL`);
} catch (e) {
  if (e?.errno !== 1060) { // ER_DUP_FIELDNAME
    // 다른 에러는 그대로 보고
    throw e;
  }
}

// --- full_addr 채우기(기록용) ---
await pool.query(`
  UPDATE listings
     SET full_addr = TRIM(CONCAT_WS(' ',
                       sigungu,
                       NULLIF(road_name, ''),
                       NULLIF(lot_no, '')
                     ))
   WHERE (full_addr IS NULL OR full_addr = '')
`);

// ---------- 유틸 ----------
const sleep = (ms) => new Promise(r => setTimeout(r, ms));

function splitSigungu(sigungu) {
  const t = String(sigungu || '').trim().split(/\s+/);
  // 일반적으로 [시/특별시, 구, 동] 이상
  const si = t[0] || '';
  const gu = t[1] || '';
  const dong = t[t.length - 1] || '';
  return { si, gu, dong };
}

// "… 119 30" → "… 119-30", "685 223" → "685-223"
function normalizeHyphen(addr) {
  // 마지막 두 토큰이 모두 숫자(또는 숫자-숫자)면 하이픈으로 합치기
  const parts = String(addr || '').trim().split(/\s+/);
  if (parts.length >= 2) {
    const a = parts[parts.length - 2];
    const b = parts[parts.length - 1];
    const isNum = (s) => /^\d+$/.test(s);
    const isNumHyphenNum = (s) => /^\d+-\d+$/.test(s);
    if (isNum(a) && isNum(b)) {
      parts.splice(parts.length - 2, 2, `${a}-${b}`);
      return parts.join(' ');
    }
    // 이미 b가 685-223 형태면 그대로 둠
    if (isNum(a) && isNumHyphenNum(b)) return parts.join(' ');
  }
  return parts.join(' ');
}

function buildCandidates(row) {
  const { si, gu, dong } = splitSigungu(row.sigungu);
  const road = String(row.road_name || '').trim();
  const lot = String(row.lot_no || '').trim();

  const cands = [];

  // 1) 도로명 우선
  if (road) {
    // "서울특별시 구 도로명" + 숫자 하이픈 정규화
    const roadAddr = normalizeHyphen(`${si} ${gu} ${road}`.replace(/\s+/g, ' ').trim());
    cands.push(roadAddr);
  }

  // 2) 지번(동 + 번지)
  if (dong && lot) {
    const lotNorm = normalizeHyphen(lot);
    const jibunAddr = `${si} ${gu} ${dong} ${lotNorm}`.replace(/\s+/g, ' ').trim();
    cands.push(jibunAddr);
  }

  // 3) 마지막 안전망(시구동만) — 중심 좌표라도
  const bare = `${si} ${gu} ${dong}`.trim();
  if (bare.split(' ').length >= 2) cands.push(bare);

  // 중복 제거
  return Array.from(new Set(cands));
}

async function geocodeOne(query) {
  const url = 'https://dapi.kakao.com/v2/local/search/address.json';
  const { data } = await axios.get(url, {
    headers: { Authorization: `KakaoAK ${KAKAO_REST_KEY}` },
    params: { query, size: 1 }, // 1건만
    timeout: 10000,
  });
  const doc = data?.documents?.[0];
  if (!doc) return null;

  // 좌표 우선순위: road_address > address
  const lat = Number.parseFloat(doc.road_address?.y ?? doc.address?.y);
  const lng = Number.parseFloat(doc.road_address?.x ?? doc.address?.x);
  if (!Number.isFinite(lat) || !Number.isFinite(lng)) return null;
  return { lat, lng };
}

// ---------- 배치 ----------
const BATCH = 300;
const SLEEP_MS = 150;
let totalUpdated = 0;

while (true) {
  const [rows] = await pool.query(
    `SELECT listing_id, sigungu, road_name, lot_no
       FROM listings
      WHERE (coord IS NULL OR (ST_X(coord)=0 AND ST_Y(coord)=0))
      LIMIT ?`,
    [BATCH]
  );
  if (rows.length === 0) break;

  for (const r of rows) {
    const candidates = buildCandidates(r);
    let hit = null;
    for (const q of candidates) {
      try {
        hit = await geocodeOne(q);
        if (hit) {
          // 성공: 좌표 저장 (POINT(lng,lat))
          await pool.execute(
            `UPDATE listings
                SET coord = ST_SRID(POINT(?, ?), 4326),
                    full_addr = ?
              WHERE listing_id = ?`,
            [hit.lng, hit.lat, q, r.listing_id]
          );
          totalUpdated++;
          if (totalUpdated % 50 === 0) {
            console.log(`✅ updated: ${totalUpdated}`);
          }
          break;
        }
      } catch (e) {
        // 429/타임아웃 등: 살짝 쉬고 다음 후보 시도
        console.error(`⚠️ ${r.listing_id} | ${q} | ${e?.response?.status ?? ''} ${e.message}`);
        await sleep(SLEEP_MS + 300);
      }
    }

    if (!hit) {
      console.log(`- miss: ${r.listing_id} | ${candidates[0] ?? '(no-candidate)'}`);
    }

    await sleep(SLEEP_MS);
  }
}

console.log(`🎉 done. total updated = ${totalUpdated}`);
await pool.end();
