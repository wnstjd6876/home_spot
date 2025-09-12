# login-db-server

## 실행 방법
1. MySQL에 homspot 데이터베이스와 users 테이블을 준비하세요.

```sql
CREATE DATABASE IF NOT EXISTS homspot DEFAULT CHARACTER SET utf8mb4;
USE homspot;
CREATE TABLE IF NOT EXISTS users (
  user_id INT AUTO_INCREMENT PRIMARY KEY,
  email VARCHAR(100) UNIQUE NOT NULL,
  password VARCHAR(200) NOT NULL,
  name VARCHAR(50),
  time_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);
```

2. .env.example을 복사해 .env로 바꾸고 DB 설정을 채우세요.

3. 설치 및 실행
```bash
npm install
npm start
```

4. 접속
- http://localhost:3000/login.html
- http://localhost:3000/sign.html
