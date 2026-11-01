import test from 'node:test';
import assert from 'node:assert/strict';
import { decodeSubscription, sniffFormat, textToLines, isBase64Config } from '../src/engine/subscription.mjs';

const links = 'vless://u@h.example.com:443?security=tls#a\ntrojan://p@1.2.3.4:443#b';
const b64 = Buffer.from(links).toString('base64');

test('plain text keeps only lines with a scheme', () => {
  assert.deepEqual(decodeSubscription(`# comment\n\n${links}\n  \nnot a link`), links.split('\n'));
});
test('base64 and url-safe unpadded base64 decode', () => {
  assert.deepEqual(decodeSubscription(b64), links.split('\n'));
  const urlSafe = b64.replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
  assert.deepEqual(decodeSubscription(urlSafe), links.split('\n'));
  assert.deepEqual(decodeSubscription(b64.replace(/(.{20})/g, '$1\n')), links.split('\n'));
});
test('short or non-config base64 is treated as plain text', () => {
  assert.equal(isBase64Config('aGVsbG8='), false);
  assert.equal(isBase64Config(Buffer.from('just some words, long enough to pass the length').toString('base64')), false);
});
test('format sniffing', () => {
  assert.equal(sniffFormat('{"outbounds":[]}'), 'singbox');
  assert.equal(sniffFormat('proxies:\n  - name: a'), 'clash');
  assert.equal(sniffFormat(b64), 'base64');
  assert.equal(sniffFormat(links), 'plain');
  assert.equal(sniffFormat('{broken'), 'plain');
  assert.deepEqual(textToLines('proxies:\n- name: a'), { format: 'clash', lines: [], supported: false });
});
