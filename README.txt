

## 실행 방법
.env 파일 생성

DB_HOST=127.0.0.1
DB_PORT=3306
DB_USER=root
DB_PASS=
DB_NAME=homespot

SESSION_SECRET=3f9b1b0ac5c24c0f8f79a6f83d3f9a4c
PORT=3000

AWS_ACCESS_KEY_ID=
AWS_SECRET_ACCESS_KEY=
AWS_REGION=ap-northeast-2
SES_FROM=

APP_BASE_URL =http://localhost:3000
APP_NAME=Homespot

KAKAO_REST_KEY=

//db 생성

mysql dump import => homespot_2025-09-12 다운

-> mysql -u root -p homespot < "본인 homespot_2025-09-12.sql 파일 위치"

3. 설치 및 실행

npm install
npm start
```

