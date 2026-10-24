import test from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import path from 'node:path';

const root = path.resolve(import.meta.dirname, '..');
const read = file => fs.readFileSync(path.join(root, file), 'utf8');

test('session and upload directories are gitignored', () => {
  const ignore = read('.gitignore');
  for (const entry of ['auth/', 'session/', 'node_modules/', 'public/audios/*', 'public/imagenes/*', 'public/archivos/*', 'public/videos/*']) {
    assert.ok(ignore.includes(entry), 'Missing ignore rule: ' + entry);
  }
});

test('tenant sessions are isolated by company and account', () => {
  const source = read('tenant-whatsapp.js');
  assert.match(source, /path\.join\(base,String\(account\.tenant_id\),String\(key\)\)/);
  assert.match(source, /useMultiFileAuthState\(dir\)/);
});

test('server has health endpoint', () => {
  assert.match(read('index.js'), /app\.get\("\/health"/);
});
