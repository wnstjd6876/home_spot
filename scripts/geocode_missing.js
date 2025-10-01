// scripts/geocode_missing.js
// 실행: node scripts/geocode_missing.js
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

// ---------- 유틸 ----------
const sleep = (ms) => new Promise((r) => setTimeout(r, ms));
const norm = (s) => (s ?? '').toString().trim();

/** sigungu 에서 [시/도, 구/군, 동] 분리 (마지막 토큰을 동으로 취급) */
function splitSigungu(sigungu) {
  const t = norm(sigungu).split(/\s+/).filter(Boolean);
  const si = t[0] || '';
  const gu = t[1] || '';
  const dong = t[t.length - 1] || '';
  return { si, gu, dong };
}

/** "… 119 30" → "… 119-30" 식의 끝 두 숫자 결합 */
function normalizeHyphen(addr) {
  const parts = norm(addr).split(/\s+/);
  if (parts.length >= 2) {
    const a = parts[parts.length - 2];
    const b = parts[parts.length - 1];
    const isNum = (s) => /^\d+$/.test(s);
    const isNumHyphenNum = (s) => /^\d+-\d+$/.test(s);
    if (isNum(a) && isNum(b)) {
      parts.splice(parts.length - 2, 2, `${a}-${b}`);
      return parts.join(' ');
    }
    if (isNum(a) && isNumHyphenNum(b)) return parts.join(' ');
  }
  return parts.join(' ');
}

/** 질의 후보 주소 생성 (중복 제거) */
function buildCandidates(row) {
  const { si, gu, dong } = splitSigungu(row.sigungu);
  const road = norm(row.road_name);
  const lot = norm(row.lot_no);

  const cands = [];

  // 1) 도로명 우선
  if (road) {
    const roadAddr = normalizeHyphen(`${si} ${gu} ${road}`.replace(/\s+/g, ' ').trim());
    cands.push(roadAddr);
  }

  // 2) 지번(동 + 번지)
  if (dong && lot) {
    const lotNorm = normalizeHyphen(lot);
    const jibunAddr = `${si} ${gu} ${dong} ${lotNorm}`.replace(/\s+/g, ' ').trim();
    cands.push(jibunAddr);
  }

  // 3) 안전망(시구동 중심좌표라도)
  const bare = `${si} ${gu} ${dong}`.trim();
  if (bare.split(' ').length >= 2) cands.push(bare);

  return Array.from(new Set(cands));
}

/** 카카오 주소검색 1회 */
async function geocodeOne(query) {
  const url = 'https://dapi.kakao.com/v2/local/search/address.json';
  const { data } = await axios.get(url, {
    headers: { Authorization: `KakaoAK ${KAKAO_REST_KEY}` },
    params: { query, size: 1 },
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

// ---------- 심플 배치 실행 ----------
// 너무 세게 때리지 않도록 소심하게…
const BATCH = 200;     // 한 번에 읽어올 행 수 (너무 크게 잡지 말기)
const SLEEP_MS = 400;  // 건당 대기 (RPS ~2.5/sec). 429 뜨면 아래에서 추가로 쉼.

let totalUpdated = 0;
let hasFullAddrColumn = true; // full_addr 없으면 한 번 에러 후 false로 바꿔서 이후엔 세팅 생략

while (true) {
  const [rows] = await pool.query(
    `SELECT listing_id, sigungu, road_name, lot_no
       FROM listings_geocode_todo
      WHERE coord IS NULL OR (ST_X(coord)=0 AND ST_Y(coord)=0)
      ORDER BY listing_id
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
          // 성공: 좌표 저장 (POINT(lng, lat)), (옵션) full_addr/lat/lng도 보관
          try {
            await pool.execute(
              `UPDATE listings_geocode_todo
                  SET coord = ST_SRID(POINT(?, ?), 4326),
                      lat = ?,
                      lng = ?,
                      full_addr = ?
                WHERE listing_id = ?`,
              [hit.lng, hit.lat, hit.lat, hit.lng, q, r.listing_id]
            );
          } catch (e) {
            // full_addr, lat/lng 컬럼이 없을 수 있으니 최소한 coord만이라도 저장
            if (e?.errno === 1054) { // Unknown column
              hasFullAddrColumn = false;
              await pool.execute(
                `UPDATE listings_geocode_todo
                    SET coord = ST_SRID(POINT(?, ?), 4326)
                  WHERE listing_id = ?`,
                [hit.lng, hit.lat, r.listing_id]
              );
            } else {
              throw e;
            }
          }

          totalUpdated++;
          if (totalUpdated % 50 === 0) {
            console.log(`✅ updated: ${totalUpdated}`);
          }
          break; // 후보 루프 탈출
        }
      } catch (e) {
        const status = e?.response?.status;
        // 429(쿼터/속도), 408/504(타임아웃) 등은 조금 더 쉬고 다음 후보 시도
        const extra = status === 429 ? 60000 : 500; // 429면 60초 휴식
        console.error(`⚠️ ${r.listing_id} | ${q} | ${status ?? ''} ${e.message} → sleep ${extra}ms`);
        await sleep(extra);
      }
    }

    if (!hit) {
      console.log(`- miss: ${r.listing_id} | ${candidates[0] ?? '(no-candidate)'}`);
    }

    // 기본 간격 (개별 후보 시도 후에도 한 템포 쉬기)
    await sleep(SLEEP_MS);
  }
}

console.log(` done. total updated = ${totalUpdated}`);
await pool.end();
