// CommonJS 버전 (require) — Node v22에서도 바로 실행됩니다.
// 실행: node extract_selective.js
// 입력:
//   - D:/DB_CSV/broker_part_02.csv ~ broker_part_06.csv
//   - D:/DB_CSV/listings_all.csv (rowhouse만 뽑기)
// 출력:
//   - D:/DB_CSV/sample_officetel.csv   (최대 30,000)
//   - D:/DB_CSV/sample_rowhouse.csv    (최대 30,000) ← listings_all.csv에서만
//   - D:/DB_CSV/sample_detached.csv    (최대 30,000)
//   - D:/DB_CSV/sample_presale_occupancy.csv (part_02~06에서 presale/occupancy 전부)

const fs = require('fs');
const path = require('path');
const csv = require('fast-csv');

const PART_INPUTS = [
  "D:/DB_CSV/broker_part_02.csv",
  "D:/DB_CSV/broker_part_03.csv",
  "D:/DB_CSV/broker_part_04.csv",
  "D:/DB_CSV/broker_part_05.csv",
  "D:/DB_CSV/broker_part_06.csv",
];

// rowhouse는 여기서만 수집
const ROWHOUSE_ONLY_INPUT = "D:/DB_CSV/listings_all.csv";

const LIMITS = {
  officetel: 30000,
  rowhouse: 30000,
  detached: 30000,
};

const OUT_DIR = "D:/DB_CSV";
const OUT_PATHS = {
  officetel: path.join(OUT_DIR, "sample_officetel.csv"),
  rowhouse: path.join(OUT_DIR, "sample_rowhouse.csv"),
  detached: path.join(OUT_DIR, "sample_detached.csv"),
  presale_occupancy: path.join(OUT_DIR, "sample_presale_occupancy.csv"),
};

const writers = {
  officetel: null,
  rowhouse: null,
  detached: null,
  presale_occupancy: null,
};
const writeStreams = {
  officetel: null,
  rowhouse: null,
  detached: null,
  presale_occupancy: null,
};
const counts = {
  officetel: 0,
  rowhouse: 0,
  detached: 0,
  presale_occupancy: 0,
};

function initWriter(key, headers) {
  if (writers[key]) return;
  const ws = fs.createWriteStream(OUT_PATHS[key], { encoding: 'utf8' });
  const fm = csv.format({ headers }); // 첫 행에서 받은 headers 그대로 사용
  fm.pipe(ws);
  writers[key] = fm;
  writeStreams[key] = ws;
}

function writeRow(key, row, headers) {
  if (!writers[key]) initWriter(key, headers);
  writers[key].write(row);
  counts[key]++;
}

function needMore(typeKey) {
  if (typeKey in LIMITS) return counts[typeKey] < LIMITS[typeKey];
  return true;
}

function processFile(file, opts = { collectTypes: true, collectPresaleOcc: true }) {
  return new Promise((resolve, reject) => {
    let headersRef = null;

    fs.createReadStream(file)
      .pipe(csv.parse({ headers: true, ignoreEmpty: true, trim: true }))
      .on('headers', (headers) => {
        headersRef = headers;
      })
      .on('data', (row) => {
        const propertyType = (row.property_type || '').trim();
        const dealType = (row.deal_type || '').trim();

        // presale/occupancy: part_02~06에서만 수집
        if (opts.collectPresaleOcc && (dealType === 'presale_right' || dealType === 'occupancy_right')) {
          writeRow('presale_occupancy', row, headersRef);
        }

        if (opts.collectTypes) {
          if (propertyType === 'officetel' && needMore('officetel')) {
            writeRow('officetel', row, headersRef);
          } else if (propertyType === 'detached' && needMore('detached')) {
            writeRow('detached', row, headersRef);
          } else if (propertyType === 'rowhouse' && needMore('rowhouse')) {
            // rowhouse는 listings_all.csv에서만 모아야 하므로
            // PART_INPUTS 처리 시에는 rowhouse 수집 안 함
            // (이 함수 호출 옵션으로 제어)
            writeRow('rowhouse', row, headersRef);
          }
        }
      })
      .on('end', (rowCount) => {
        console.log(`[OK] ${path.basename(file)} parsed rows: ${rowCount}`);
        resolve();
      })
      .on('error', (err) => {
        console.error(`[ERR] ${file}:`, err);
        reject(err);
      });
  });
}

async function main() {
  console.log('=== Start extracting ===');

  // 1) part_02~06: officetel/detached 수집 + presale/occupancy 전부 수집
  for (const f of PART_INPUTS) {
    await processFile(f, { collectTypes: true, collectPresaleOcc: true });
    console.log(`Progress -> officetel: ${counts.officetel}/${LIMITS.officetel}, detached: ${counts.detached}/${LIMITS.detached}, presale_occupancy: ${counts.presale_occupancy}`);
  }

  // 2) listings_all.csv: rowhouse만 수집
  await processFile(ROWHOUSE_ONLY_INPUT, { collectTypes: true, collectPresaleOcc: false });

  // 마무리: writer 닫기
  for (const key of Object.keys(writers)) {
    if (writers[key]) writers[key].end();
    if (writeStreams[key] && writeStreams[key].close) writeStreams[key].close();
  }

  console.log('=== Done ===');
  console.log(`Output:
 - ${OUT_PATHS.officetel} (${counts.officetel} rows)
 - ${OUT_PATHS.rowhouse} (${counts.rowhouse} rows)
 - ${OUT_PATHS.detached} (${counts.detached} rows)
 - ${OUT_PATHS.presale_occupancy} (${counts.presale_occupancy} rows)`);
}

main().catch((e) => {
  console.error('Fatal:', e);
  process.exit(1);
});
