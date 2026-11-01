// A port of the parts of PyYAML's emitter (yaml.dump(data, sort_keys=False, allow_unicode=True))
// that the Clash export exercises: block mappings and sequences, empty collections, and the
// plain / single-quoted / double-quoted scalar styles with width-80 folding.
// Strings are handled as arrays of code points, like Python.
import { PyFloat, pyFloatStr } from './pycompat.mjs';

const BEST_INDENT = 2;
const BEST_WIDTH = 80;
const BREAKS = '\n\x85';
const SPACES_BREAKS = '\0 \t\r\n\x85';

// YAML 1.1 implicit resolvers (PyYAML). `$` in Python also matches before a final newline.
const RESOLVERS = [
  ['bool', /^(?:yes|Yes|YES|no|No|NO|true|True|TRUE|false|False|FALSE|on|On|ON|off|Off|OFF)\n?$/, 'yYnNtTfFoO'],
  ['float', /^(?:[-+]?(?:[0-9][0-9_]*)\.[0-9_]*(?:[eE][-+][0-9]+)?|\.[0-9][0-9_]*(?:[eE][-+][0-9]+)?|[-+]?[0-9][0-9_]*(?::[0-5]?[0-9])+\.[0-9_]*|[-+]?\.(?:inf|Inf|INF)|\.(?:nan|NaN|NAN))\n?$/, '-+0123456789.'],
  ['int', /^(?:[-+]?0b[0-1_]+|[-+]?0[0-7_]+|[-+]?(?:0|[1-9][0-9_]*)|[-+]?0x[0-9a-fA-F_]+|[-+]?[1-9][0-9_]*(?::[0-5]?[0-9])+)\n?$/, '-+0123456789'],
  ['merge', /^(?:<<)\n?$/, '<'],
  ['null', /^(?:~|null|Null|NULL|)\n?$/, ['~', 'n', 'N', '']],
  ['timestamp', /^(?:[0-9][0-9][0-9][0-9]-[0-9][0-9]-[0-9][0-9]|[0-9][0-9][0-9][0-9]-[0-9][0-9]?-[0-9][0-9]?(?:[Tt]|[ \t]+)[0-9][0-9]?:[0-9][0-9]:[0-9][0-9](?:\.[0-9]*)?(?:[ \t]*(?:Z|[-+][0-9][0-9]?(?::[0-9][0-9])?))?)\n?$/, '0123456789'],
  ['value', /^(?:=)\n?$/, '='],
];

// the tag a plain scalar would be read back as (null for plain str)
function implicitTag(value) {
  const first = value === '' ? '' : value[0];
  for (const [tag, re, firsts] of RESOLVERS) {
    const hit = Array.isArray(firsts) ? firsts.includes(first) : (first !== '' && firsts.includes(first));
    if (hit && re.test(value)) return tag;
  }
  return 'str';
}

function analyze(cpArr) {
  const s = cpArr;
  if (!s.length) {
    return { empty: true, multiline: false, allowFlowPlain: false, allowBlockPlain: true, allowSingle: true, allowDouble: true };
  }
  let blockInd = false; let flowInd = false; let lineBreaks = false; let special = false;
  let leadingSpace = false; let leadingBreak = false; let trailingSpace = false; let trailingBreak = false;
  let breakSpace = false; let spaceBreak = false;
  const str = s.join('');
  if (str.startsWith('---') || str.startsWith('...')) { blockInd = true; flowInd = true; }
  let precededByWs = true;
  let followedByWs = s.length === 1 || SPACES_BREAKS.includes(s[1]);
  let prevSpace = false;
  let prevBreak = false;
  let index = 0;
  while (index < s.length) {
    const ch = s[index];
    const cp = ch.codePointAt(0);
    if (index === 0) {
      if ('#,[]{}&*!|>\'"%@`'.includes(ch)) { flowInd = true; blockInd = true; }
      if (ch === '?' || ch === ':') { flowInd = true; if (followedByWs) blockInd = true; }
      if (ch === '-' && followedByWs) { flowInd = true; blockInd = true; }
    } else {
      if (',?[]{}'.includes(ch)) flowInd = true;
      if (ch === ':') { flowInd = true; if (followedByWs) blockInd = true; }
      if (ch === '#' && precededByWs) { flowInd = true; blockInd = true; }
    }
    if (BREAKS.includes(ch)) lineBreaks = true;
    if (!(ch === '\n' || (cp >= 0x20 && cp <= 0x7e))) {
      const printable = cp === 0x85 || (cp >= 0xa0 && cp <= 0xd7ff) || (cp >= 0xe000 && cp <= 0xfffd) ||
        (cp >= 0x10000 && cp < 0x10ffff);
      if (!(printable && cp !== 0xfeff)) special = true;     // allow_unicode=True
    }
    if (ch === ' ') {
      if (index === 0) leadingSpace = true;
      if (index === s.length - 1) trailingSpace = true;
      if (prevBreak) breakSpace = true;
      prevSpace = true; prevBreak = false;
    } else if (BREAKS.includes(ch)) {
      if (index === 0) leadingBreak = true;
      if (index === s.length - 1) trailingBreak = true;
      if (prevSpace) spaceBreak = true;
      prevSpace = false; prevBreak = true;
    } else { prevSpace = false; prevBreak = false; }
    index += 1;
    precededByWs = SPACES_BREAKS.includes(ch);
    followedByWs = index + 1 >= s.length || SPACES_BREAKS.includes(s[index + 1]);
  }
  let allowFlowPlain = true; let allowBlockPlain = true; let allowSingle = true; let allowDouble = true;
  if (leadingSpace || leadingBreak || trailingSpace || trailingBreak) { allowFlowPlain = false; allowBlockPlain = false; }
  if (breakSpace) { allowFlowPlain = false; allowBlockPlain = false; allowSingle = false; }
  if (spaceBreak || special) { allowFlowPlain = false; allowBlockPlain = false; allowSingle = false; }
  if (lineBreaks) { allowFlowPlain = false; allowBlockPlain = false; }
  if (flowInd) allowFlowPlain = false;
  if (blockInd) allowBlockPlain = false;
  return { empty: false, multiline: lineBreaks, allowFlowPlain, allowBlockPlain, allowSingle, allowDouble };
}

const ESCAPES = { '\0': '0', '\x07': 'a', '\x08': 'b', '\t': 't', '\n': 'n', '\x0b': 'v', '\x0c': 'f', '\r': 'r',
  '\x1b': 'e', '"': '"', '\\': '\\', '\x85': 'N', '\xa0': '_', '': 'L', '': 'P' };

class Emitter {
  constructor() {
    this.out = '';
    this.indent = null;
    this.indents = [];
    this.column = 0;
    this.whitespace = true;
    this.indention = true;
    this.mappingContext = false;
    this.simpleKeyContext = false;
    this.flowLevel = 0;
  }

  write(s) { this.out += s; }

  writeIndent() {
    const indent = this.indent ?? 0;
    if (!this.indention || this.column > indent || (this.column === indent && !this.whitespace)) this.writeLineBreak();
    if (this.column < indent) {
      this.whitespace = true;
      this.write(' '.repeat(indent - this.column));
      this.column = indent;
    }
  }

  writeLineBreak() {
    this.whitespace = true; this.indention = true; this.column = 0; this.write('\n');
  }

  writeIndicator(ind, needWs, whitespace = false, indention = false) {
    const data = this.whitespace || !needWs ? ind : ' ' + ind;
    this.whitespace = whitespace;
    this.indention = this.indention && indention;
    this.column += data.length;
    this.write(data);
  }

  increaseIndent(flow = false, indentless = false) {
    this.indents.push(this.indent);
    if (this.indent === null) this.indent = flow ? BEST_INDENT : 0;
    else if (!indentless) this.indent += BEST_INDENT;
  }

  // ---- scalars
  chooseStyle(value, tagImplicit, analysis) {
    if (tagImplicit && !(this.simpleKeyContext && (analysis.empty || analysis.multiline)) &&
        ((this.flowLevel && analysis.allowFlowPlain) || (!this.flowLevel && analysis.allowBlockPlain))) return '';
    if (analysis.allowSingle && !(this.simpleKeyContext && analysis.multiline)) return "'";
    return '"';
  }

  scalar(value, tagImplicit) {
    const cps = Array.from(value);
    const analysis = analyze(cps);
    const style = this.chooseStyle(value, tagImplicit, analysis);
    this.increaseIndent(true);
    if (style === '') this.writePlain(cps);
    else if (style === "'") this.writeSingleQuoted(cps);
    else this.writeDoubleQuoted(cps);
    this.indent = this.indents.pop();
  }

  advance(data) { this.column += data.length; this.write(data); }

  writePlain(text) {
    if (!text.length) return;
    if (!this.whitespace) { this.column += 1; this.write(' '); }
    this.whitespace = false; this.indention = false;
    let spaces = false; let breaks = false; let start = 0; let end = 0;
    while (end <= text.length) {
      const ch = end < text.length ? text[end] : null;
      if (spaces) {
        if (ch !== ' ') {
          if (start + 1 === end && this.column > BEST_WIDTH) {
            this.writeIndent(); this.whitespace = false; this.indention = false;
          } else this.advance(text.slice(start, end).join(''));
          start = end;
        }
      } else if (breaks) {
        if (ch === null || !BREAKS.includes(ch)) {
          if (text[start] === '\n') this.writeLineBreak();
          for (const br of text.slice(start, end)) { if (br === '\n') this.writeLineBreak(); else this.writeLineBreak(); }
          this.writeIndent(); this.whitespace = false; this.indention = false;
          start = end;
        }
      } else if (ch === null || ' \n\x85'.includes(ch)) {
        this.advance(text.slice(start, end).join(''));
        start = end;
      }
      if (ch !== null) { spaces = ch === ' '; breaks = BREAKS.includes(ch); }
      end += 1;
    }
  }

  writeSingleQuoted(text) {
    this.writeIndicator("'", true);
    let spaces = false; let breaks = false; let start = 0; let end = 0;
    while (end <= text.length) {
      const ch = end < text.length ? text[end] : null;
      if (spaces) {
        if (ch === null || ch !== ' ') {
          if (start + 1 === end && this.column > BEST_WIDTH && start !== 0 && end !== text.length) this.writeIndent();
          else this.advance(text.slice(start, end).join(''));
          start = end;
        }
      } else if (breaks) {
        if (ch === null || !BREAKS.includes(ch)) {
          if (text[start] === '\n') this.writeLineBreak();
          for (const br of text.slice(start, end)) { if (br === '\n') this.writeLineBreak(); else this.writeLineBreak(); }
          this.writeIndent();
          start = end;
        }
      } else if (ch === null || ' \n\x85'.includes(ch) || ch === "'") {
        if (start < end) { this.advance(text.slice(start, end).join('')); start = end; }
      }
      if (ch === "'") { this.advance("''"); start = end + 1; }
      if (ch !== null) { spaces = ch === ' '; breaks = BREAKS.includes(ch); }
      end += 1;
    }
    this.writeIndicator("'", false);
  }

  writeDoubleQuoted(text) {
    this.writeIndicator('"', true);
    let start = 0; let end = 0;
    while (end <= text.length) {
      const ch = end < text.length ? text[end] : null;
      const cp = ch === null ? 0 : ch.codePointAt(0);
      if (ch === null || '"\\\x85﻿'.includes(ch) ||
          !((cp >= 0x20 && cp <= 0x7e) || ((cp >= 0xa0 && cp <= 0xd7ff) || (cp >= 0xe000 && cp <= 0xfffd)))) {
        if (start < end) { this.advance(text.slice(start, end).join('')); start = end; }
        if (ch !== null) {
          let data;
          if (Object.prototype.hasOwnProperty.call(ESCAPES, ch)) data = '\\' + ESCAPES[ch];
          else if (cp <= 0xff) data = '\\x' + cp.toString(16).toUpperCase().padStart(2, '0');
          else if (cp <= 0xffff) data = '\\u' + cp.toString(16).toUpperCase().padStart(4, '0');
          else data = '\\U' + cp.toString(16).toUpperCase().padStart(8, '0');
          this.advance(data);
          start = end + 1;
        }
      }
      if (end > 0 && end < text.length - 1 && (ch === ' ' || start >= end) && this.column + (end - start) > BEST_WIDTH) {
        const data = text.slice(start, end).join('') + '\\';
        if (start < end) start = end;
        this.advance(data);
        this.writeIndent(); this.whitespace = false; this.indention = false;
        if (text[start] === ' ') this.advance('\\');
      }
      end += 1;
    }
    this.writeIndicator('"', false);
  }

  // ---- nodes
  node(v, { mapping = false, sequence = false, simpleKey = false } = {}) {
    this.mappingContext = mapping;
    this.simpleKeyContext = simpleKey;
    if (Array.isArray(v)) {
      if (this.flowLevel || v.length === 0) this.flowSeq(v); else this.blockSeq(v);
    } else if (v !== null && typeof v === 'object' && !(v instanceof PyFloat)) {
      if (this.flowLevel || Object.keys(v).length === 0) this.flowMap(v); else this.blockMap(v);
    } else {
      this.scalarNode(v);
    }
    void sequence;
  }

  scalarNode(v) {
    let text; let implicit;
    if (v === null || v === undefined) { text = 'null'; implicit = true; }
    else if (typeof v === 'boolean') { text = v ? 'true' : 'false'; implicit = true; }
    else if (typeof v === 'number' || typeof v === 'bigint') { text = String(v); implicit = true; }
    else if (v instanceof PyFloat) { text = pyFloatStr(v.v); implicit = true; }
    else { text = String(v); implicit = implicitTag(text) === 'str'; }
    this.scalar(text, implicit);
  }

  flowSeq(v) {
    this.writeIndicator('[', true, true);
    this.flowLevel += 1;
    this.increaseIndent(true);
    v.forEach((item, i) => {
      if (i) this.writeIndicator(',', false);
      this.node(item, { sequence: true });
    });
    this.indent = this.indents.pop();
    this.flowLevel -= 1;
    this.writeIndicator(']', false);
  }

  flowMap(o) {
    this.writeIndicator('{', true, true);
    this.flowLevel += 1;
    this.increaseIndent(true);
    Object.keys(o).forEach((k, i) => {
      if (i) this.writeIndicator(',', false);
      this.node(k, { mapping: true, simpleKey: true });
      this.writeIndicator(':', false);
      this.node(o[k], { mapping: true });
    });
    this.indent = this.indents.pop();
    this.flowLevel -= 1;
    this.writeIndicator('}', false);
  }

  blockSeq(v) {
    const indentless = this.mappingContext && !this.indention;
    this.increaseIndent(false, indentless);
    for (const item of v) {
      this.writeIndent();
      this.writeIndicator('-', true, false, true);
      this.node(item, { sequence: true });
    }
    this.indent = this.indents.pop();
  }

  blockMap(o) {
    this.increaseIndent(false);
    for (const k of Object.keys(o)) {
      this.writeIndent();
      this.node(k, { mapping: true, simpleKey: true });
      this.writeIndicator(':', false);
      this.node(o[k], { mapping: true });
    }
    this.indent = this.indents.pop();
  }
}

export function yamlDump(data) {
  const e = new Emitter();
  e.node(data);
  e.writeIndent();
  return e.out;
}

// yaml.dump({"proxies": proxies}, sort_keys=False, allow_unicode=True)
export const dumpClashYaml = (proxies) => yamlDump({ proxies });
