import test from 'node:test';
import assert from 'node:assert/strict';
import { isIPv4, isIPv6 } from 'node:net';
import { DNS_CATEGORIES, DNS_PRESETS } from '../src/engine/dns-presets.mjs';

test('every DNS preset has valid addresses and a known category', () => {
  const cats = new Set(DNS_CATEGORIES.map((c) => c.id));
  const ids = new Set();
  for (const p of DNS_PRESETS) {
    assert.ok(!ids.has(p.id), p.id);
    ids.add(p.id);
    assert.ok(cats.has(p.category), p.id);
    assert.ok(p.v4.length > 0 && p.v4.every(isIPv4), p.id);
    assert.ok(p.v6.every(isIPv6), p.id);
    assert.ok(!p.doh || p.doh.startsWith('https://'), p.id);
  }
});

test('the catalog covers ads, privacy, malware, family and anti-sanction servers', () => {
  const have = new Set(DNS_PRESETS.map((p) => p.category));
  for (const c of ['ads', 'privacy', 'malware', 'family', 'sanctions']) assert.ok(have.has(c), c);
});
