@echo off
chcp 65001 > nul
cd /d "%~dp0"
if not exist node_modules (
  echo 처음 실행이라 필요한 파일을 설치합니다...
  call npm install
)
node server.js
pause
