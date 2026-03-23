#!/usr/bin/env node
/**
 * Encrypt dashboard data files with AES-256-GCM (PBKDF2-derived key).
 * Password is read from the DASHBOARD_PASSWORD environment variable.
 *
 * A SINGLE salt is generated per deploy and shared across all files.
 * The salt is stored only in aggregates.json.enc (the probe file) so the
 * browser can derive the same key for every other .enc file in one step.
 *
 * aggregates.json.enc envelope: { "salt": "<b64>", "iv": "<b64>", "data": "<b64>" }
 * all other .enc envelopes:      {                  "iv": "<b64>", "data": "<b64>" }
 * where "data" is ciphertext || 16-byte GCM auth tag (Web Crypto API compatible).
 *
 * Run from the repository root:
 *   node scripts/encrypt_data.js
 */

'use strict';

const crypto = require('crypto');
const fs = require('fs');
const path = require('path');

function encryptBytes(key, plaintext, includeSalt = false, salt = null) {
  const iv = crypto.randomBytes(12);
  const cipher = crypto.createCipheriv('aes-256-gcm', key, iv);
  const ciphertext = Buffer.concat([cipher.update(plaintext), cipher.final()]);
  const tag = cipher.getAuthTag();
  const envelope = {
    iv: iv.toString('base64'),
    data: Buffer.concat([ciphertext, tag]).toString('base64'),
  };
  if (includeSalt && salt) {
    envelope.salt = salt.toString('base64');
  }
  return envelope;
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

  // Generate ONE salt for the entire deploy.
  // Store it only in the probe file (aggregates.json.enc) so the browser
  // can derive the same key used for all other .enc files.
  const salt = crypto.randomBytes(16);
  const key = crypto.pbkdf2Sync(password, salt, 100_000, 32, 'sha256');

  const dataDir = path.join(docsDir, 'data');

  // Write LATAM / Africa secrets to JSON files so they can be encrypted.
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

  // aggregates.json is the probe file — its envelope includes the shared salt.
  // All other files omit the salt (they use the same key).
  const targets = [
    { name: 'aggregates.json', includeSalt: true },
    { name: 'journals.json',             includeSalt: false },
    { name: 'meta.json',                 includeSalt: false },
    { name: 'applications.json',         includeSalt: false },
    { name: 'latam_applications.json',   includeSalt: false },
    { name: 'africa_applications.json',  includeSalt: false },
  ];

  for (const { name, includeSalt } of targets) {
    const src = path.join(dataDir, name);
    const dst = src + '.enc';
    if (!fs.existsSync(src)) {
      console.log(`Skipped ${name} (not found).`);
      continue;
    }
    const plaintext = fs.readFileSync(src);
    const payload = encryptBytes(key, plaintext, includeSalt, salt);
    fs.writeFileSync(dst, JSON.stringify(payload), 'utf8');
    fs.unlinkSync(src);
    console.log(`Encrypted ${name} \u2192 ${name}.enc`);
  }

  // config.js only needs to tell the browser that encryption is active.
  // The salt lives in aggregates.json.enc, not here.
  fs.writeFileSync(configPath, 'window.ENCRYPTION_ENABLED = true;\n', 'utf8');
  console.log('Wrote config.js.');
}

main();
