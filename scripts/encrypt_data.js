#!/usr/bin/env node
/**
 * Encrypt dashboard data files with AES-256-GCM (PBKDF2-derived key).
 * Password is read from the DASHBOARD_PASSWORD environment variable.
 *
 * A SINGLE salt is generated per deploy and shared across all files.
 * The salt is written to docs/config.js as window.ENCRYPTION_SALT so the
 * browser can derive the same key for every .enc file.
 *
 * Each output .enc file is a JSON object:
 *   { "iv": "<base64>", "data": "<base64>" }
 * where "data" is ciphertext || 16-byte GCM auth tag (Web Crypto API compatible).
 *
 * Run from the repository root:
 *   node scripts/encrypt_data.js
 */

'use strict';

const crypto = require('crypto');
const fs = require('fs');
const path = require('path');

function encryptBytes(key, plaintext) {
  const iv = crypto.randomBytes(12);
  const cipher = crypto.createCipheriv('aes-256-gcm', key, iv);
  const ciphertext = Buffer.concat([cipher.update(plaintext), cipher.final()]);
  const tag = cipher.getAuthTag(); // 16 bytes by default
  return {
    iv: iv.toString('base64'),
    // Web Crypto AES-GCM decrypt expects the auth tag appended to the ciphertext
    data: Buffer.concat([ciphertext, tag]).toString('base64'),
  };
}

function main() {
  const password = (process.env.DASHBOARD_PASSWORD || '').trim();
  const docsDir = path.resolve(__dirname, '..', 'docs');
  const configPath = path.join(docsDir, 'config.js');

  if (!password) {
    console.error('DASHBOARD_PASSWORD not set — skipping encryption.');
    fs.writeFileSync(configPath, 'window.ENCRYPTION_ENABLED = false;\n', 'utf8');
    return;
  }

  // Generate ONE salt for the entire deploy. The key derived from this salt
  // is the same for every .enc file, so the browser only needs to derive it once.
  const salt = crypto.randomBytes(16);
  const key = crypto.pbkdf2Sync(password, salt, 100_000, 32, 'sha256');
  const saltB64 = salt.toString('base64');

  const dataDir = path.join(docsDir, 'data');

  // Write LATAM / Africa secrets to JSON files so they are encrypted along
  // with the other data assets and never stored in plain text.
  for (const [envVar, filename] of [
    ['LATAM_APPLICATIONS_DATA', 'latam_applications.json'],
    ['AFRICA_APPLICATIONS_DATA', 'africa_applications.json'],
  ]) {
    const raw = (process.env[envVar] || '').trim();
    if (raw && !['null', 'none', ''].includes(raw.toLowerCase())) {
      fs.writeFileSync(path.join(dataDir, filename), raw, 'utf8');
      console.log(`Wrote ${filename} from secret.`);
    }
  }

  const targets = [
    'journals.json',
    'aggregates.json',
    'meta.json',
    'applications.json',
    'latam_applications.json',
    'africa_applications.json',
  ];

  for (const name of targets) {
    const src = path.join(dataDir, name);
    const dst = src + '.enc';
    if (!fs.existsSync(src)) {
      console.log(`Skipped ${name} (not found).`);
      continue;
    }
    const plaintext = fs.readFileSync(src);
    const payload = encryptBytes(key, plaintext);
    fs.writeFileSync(dst, JSON.stringify(payload), 'utf8');
    fs.unlinkSync(src);
    console.log(`Encrypted ${name} \u2192 ${name}.enc`);
  }

  // Write config.js with the salt so the browser can derive the same key.
  // The salt is not secret — it only slows down offline brute-force attacks.
  fs.writeFileSync(
    configPath,
    `window.ENCRYPTION_ENABLED = true;\nwindow.ENCRYPTION_SALT = "${saltB64}";\n`,
    'utf8'
  );
  console.log('Wrote config.js with ENCRYPTION_SALT.');
}

main();
