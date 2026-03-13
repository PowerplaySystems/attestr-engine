#!/usr/bin/env node
const { execSync, spawn } = require('child_process');
const path = require('path');

process.chdir(__dirname);

const tsx = path.join(__dirname, 'node_modules', 'tsx', 'dist', 'cli.mjs');
const child = spawn(process.execPath, [tsx, 'watch', 'src/index.ts'], {
  stdio: 'inherit',
  cwd: __dirname,
});

child.on('exit', (code) => process.exit(code || 0));
