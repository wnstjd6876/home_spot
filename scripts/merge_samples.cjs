// merge_samples.cjs
const fs = require("fs");

const inputs = [
  "D:/DB_CSV/sample_officetel.csv",
  "D:/DB_CSV/sample_rowhouse.csv",
  "D:/DB_CSV/sample_detached.csv"
];

const output = "D:/DB_CSV/sample_merged.csv";

// 첫 파일의 내용을 그대로 복사 (헤더 포함)
fs.copyFileSync(inputs[0], output);

// 나머지 파일은 헤더 줄 빼고 이어붙이기
for (let i = 1; i < inputs.length; i++) {
  const lines = fs.readFileSync(inputs[i], "utf8").split(/\r?\n/);
  const noHeader = lines.slice(1).join("\n");
  fs.appendFileSync(output, "\n" + noHeader);
}

console.log("Merged CSV created:", output);
