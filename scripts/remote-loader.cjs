'use strict';
const { createPrivateKey, createPublicKey, privateDecrypt, createDecipheriv, verify, createHash, constants } = require('node:crypto');

const WIRE_LIMIT = 650 * 1024, SIGNED_LIMIT = 480 * 1024, SCRIPT_LIMIT = 256 * 1024;
const fail = () => { throw new Error('Remote customization verification failed'); };
const object = (value, keys) => value && typeof value === 'object' && !Array.isArray(value) && Object.keys(value).sort().join(',') === keys;
function decode(value) {
  if (typeof value !== 'string' || !/^[A-Za-z0-9_-]*$/.test(value)) fail();
  const decoded = Buffer.from(value, 'base64url');
  if (decoded.toString('base64url') !== value) fail();
  return decoded;
}
const text = bytes => new TextDecoder('utf-8', { fatal: true }).decode(bytes);
const json = part => JSON.parse(text(decode(part)));

function validatePolicy(policy) {
  const url = new URL(policy.url);
  if (url.username || url.password || url.hash || url.search || !/^\/v\/[A-Za-z0-9_-]{43}$/.test(url.pathname) ||
      (url.protocol !== 'https:' && !(url.protocol === 'http:' && ['localhost', '127.0.0.1', '[::1]'].includes(url.hostname)))) fail();
  if (typeof policy.key !== 'string' || !policy.key.trim() || Buffer.byteLength(policy.key) > 256 || /[\x00-\x1f\x7f]/.test(policy.key) ||
      !Number.isSafeInteger(policy.minimumVersion) || policy.minimumVersion < 1) fail();
  for (const value of [policy.verificationKey, policy.decryptionKey]) if (typeof value !== 'string' || value.length > 16000) fail();
  const verificationKey = createPublicKey(policy.verificationKey), decryptionKey = createPrivateKey(policy.decryptionKey);
  if (verificationKey.asymmetricKeyType !== 'ed25519' || decryptionKey.asymmetricKeyType !== 'rsa' ||
      ![2048, 3072, 4096].includes(decryptionKey.asymmetricKeyDetails.modulusLength)) fail();
  return { url, verificationKey, decryptionKey };
}

function verifyScript(raw, policy, now = Date.now()) {
  const keys = validatePolicy(policy);
  if (typeof raw !== 'string' || raw.length > WIRE_LIMIT) fail();
  const parts = raw.split('.');
  if (parts.length !== 5 || parts[0].length > 4096) fail();
  const header = json(parts[0]);
  if (!object(header, 'alg,cty,enc,jwk,typ') || header.alg !== 'RSA-OAEP-256' || header.enc !== 'A256GCM' ||
      header.typ !== 'cf-kv+jwe' || header.cty !== 'application/jose' || !object(header.jwk, 'e,kty,n')) fail();
  const recipient = createPublicKey(keys.decryptionKey).export({ format: 'jwk' });
  if (header.jwk.kty !== 'RSA' || header.jwk.e !== 'AQAB' || header.jwk.n !== recipient.n || header.jwk.e !== recipient.e) fail();
  const wrapped = decode(parts[1]), iv = decode(parts[2]), ciphertext = decode(parts[3]), tag = decode(parts[4]);
  if (wrapped.length !== decode(recipient.n).length || iv.length !== 12 || tag.length !== 16 || ciphertext.length > SIGNED_LIMIT) fail();
  const cek = privateDecrypt({ key: keys.decryptionKey, padding: constants.RSA_PKCS1_OAEP_PADDING, oaepHash: 'sha256' }, wrapped);
  if (cek.length !== 32) fail();
  const decipher = createDecipheriv('aes-256-gcm', cek, iv, { authTagLength: 16 });
  decipher.setAAD(Buffer.from(parts[0], 'ascii')); decipher.setAuthTag(tag);
  const signed = text(Buffer.concat([decipher.update(ciphertext), decipher.final()]));
  if (signed.length > SIGNED_LIMIT) fail();
  const jws = signed.split('.');
  if (jws.length !== 3 || jws[0].length > 512) fail();
  const signingHeader = json(jws[0]), signature = decode(jws[2]);
  if (!object(signingHeader, 'alg,typ') || signingHeader.alg !== 'Ed25519' || signingHeader.typ !== 'cf-kv+jws' || signature.length !== 64 ||
      !verify(null, Buffer.from(jws[0] + '.' + jws[1], 'ascii'), keys.verificationKey, signature)) fail();
  const claims = json(jws[1]);
  if (!object(claims, 'encoding,expiresAt,format,issuedAt,key,schema,value,version') || claims.schema !== 1 || claims.encoding !== 'base64url' ||
      claims.format !== 'text' || claims.key !== policy.key || !Number.isSafeInteger(claims.version) || claims.version < policy.minimumVersion ||
      !Number.isSafeInteger(claims.issuedAt) || claims.issuedAt < 0 || claims.issuedAt > 8640000000000000 || claims.issuedAt > now + 60000 ||
      (claims.expiresAt !== null && (!Number.isSafeInteger(claims.expiresAt) || claims.expiresAt <= claims.issuedAt || claims.expiresAt <= now || claims.expiresAt > 8640000000000000))) fail();
  const bytes = decode(claims.value);
  if (!bytes.length || bytes.length > SCRIPT_LIMIT) fail();
  const script = text(bytes);
  if (!script.startsWith('#!/usr/bin/env bash\n') && !script.startsWith('#!/bin/bash\n')) fail();
  return { script, version: claims.version, sha256: createHash('sha256').update(bytes).digest('hex') };
}

async function loadScript(policy, fetcher = fetch) {
  const { url } = validatePolicy(policy);
  const response = await fetcher(url, { redirect: 'error', cache: 'no-store', signal: AbortSignal.timeout(30000) });
  if (response.status !== 200 || response.headers.get('Content-Type')?.split(';')[0] !== 'application/jose' || Number(response.headers.get('Content-Length')) > WIRE_LIMIT || !response.body) fail();
  const reader = response.body.getReader(), chunks = [];
  let length = 0;
  try {
    while (true) {
      const chunk = await reader.read();
      if (chunk.done) break;
      length += chunk.value.byteLength;
      if (length > WIRE_LIMIT) fail();
      chunks.push(chunk.value);
    }
  } catch (error) { await reader.cancel().catch(() => {}); throw error; }
  finally { reader.releaseLock(); }
  return verifyScript(text(Buffer.concat(chunks)), policy);
}

module.exports = { validatePolicy, verifyScript, loadScript };
