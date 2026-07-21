import { spawn } from 'node:child_process';
import { existsSync } from 'node:fs';

const python = existsSync('.venv/bin/python') ? '.venv/bin/python' : 'python3';

const children = [
  spawn('node', ['server/index.js'], {
    stdio: 'inherit',
    env: { ...process.env, CONTROLX_API_PORT: '8787' }
  }),
  spawn(python, ['-m', 'uvicorn', 'backend.main:app', '--host', '127.0.0.1', '--port', '8000'], { stdio: 'inherit', env: process.env }),
  spawn('npx', ['vite', '--host', '127.0.0.1', '--port', '5173'], { stdio: 'inherit', env: process.env })
];

function shutdown(signal) {
  for (const child of children) {
    child.kill(signal);
  }
}

process.on('SIGINT', () => {
  shutdown('SIGINT');
  process.exit(0);
});

process.on('SIGTERM', () => {
  shutdown('SIGTERM');
  process.exit(0);
});

for (const child of children) {
  child.on('exit', (code) => {
    if (code && code !== 0) {
      shutdown('SIGTERM');
      process.exit(code);
    }
  });
}
