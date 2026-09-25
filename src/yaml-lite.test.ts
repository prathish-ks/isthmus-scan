import { describe, expect, it } from 'vitest';

import { findKey, mappingUnder, readYamlLite, sequenceUnder } from './yaml-lite.js';

describe('readYamlLite', () => {
  it('records a top-level key with an empty path', () => {
    const r = readYamlLite('minimumReleaseAge: 4320\n');
    expect(findKey(r, 'minimumReleaseAge')[0]).toMatchObject({ value: '4320', indent: 0, path: [], line: 1 });
  });

  it('records a nested key with its enclosing path — the distinction the whole file exists for', () => {
    const r = readYamlLite('pnpm:\n  minimumReleaseAge: 4320\n');
    expect(findKey(r, 'minimumReleaseAge')[0]).toMatchObject({ value: '4320', path: ['pnpm'], line: 2 });
  });

  it('tracks nesting several levels deep', () => {
    const r = readYamlLite('a:\n  b:\n    c: 1\n');
    expect(findKey(r, 'c')[0].path).toEqual(['a', 'b']);
  });

  it('unwinds the path when indentation decreases', () => {
    const r = readYamlLite('a:\n  b: 1\nc: 2\n');
    expect(findKey(r, 'b')[0].path).toEqual(['a']);
    expect(findKey(r, 'c')[0].path).toEqual([]);
  });

  it('reads sequence items under the key that opened them', () => {
    const r = readYamlLite('onlyBuiltDependencies:\n  - esbuild\n  - sharp\n');
    const entry = findKey(r, 'onlyBuiltDependencies')[0];
    expect(sequenceUnder(r, entry)).toEqual(['esbuild', 'sharp']);
  });

  it('reads a mapping block under a key', () => {
    const r = readYamlLite('minimumReleaseAgeExclude:\n  left-pad: "1.2.3"\n');
    const entry = findKey(r, 'minimumReleaseAgeExclude')[0];
    expect(mappingUnder(r, entry).map((e) => [e.key, e.value])).toEqual([['left-pad', '1.2.3']]);
  });

  it('does not attribute a sibling sequence to the wrong key', () => {
    const r = readYamlLite('first:\n  - a\nsecond:\n  - b\n');
    expect(sequenceUnder(r, findKey(r, 'first')[0])).toEqual(['a']);
    expect(sequenceUnder(r, findKey(r, 'second')[0])).toEqual(['b']);
  });

  it('strips comments but keeps a # inside a quoted value', () => {
    const r = readYamlLite('a: 1 # trailing comment\nb: "has # inside"\n');
    expect(findKey(r, 'a')[0].value).toBe('1');
    expect(findKey(r, 'b')[0].value).toBe('has # inside');
  });

  it('ignores blank and comment-only lines without shifting line numbers', () => {
    const r = readYamlLite('# header\n\nkey: value\n');
    expect(findKey(r, 'key')[0].line).toBe(3);
  });

  it('unquotes single- and double-quoted scalars', () => {
    const r = readYamlLite(`a: "x"\nb: 'y'\n`);
    expect(findKey(r, 'a')[0].value).toBe('x');
    expect(findKey(r, 'b')[0].value).toBe('y');
  });

  describe('reports constructs it cannot handle rather than guessing', () => {
    it('flags flow mappings', () => {
      expect(readYamlLite('pnpm: { minimumReleaseAge: 4320 }\n').unparseable).toMatch(/flow-style/);
    });

    it('flags flow sequences', () => {
      expect(readYamlLite('onlyBuiltDependencies: [esbuild]\n').unparseable).toMatch(/flow-style/);
    });

    it('flags anchors and aliases', () => {
      expect(readYamlLite('a: &anchor\nb: *anchor\n').unparseable).toMatch(/anchor or alias/);
    });

    it('flags block scalars', () => {
      expect(readYamlLite('a: |\n  text\n').unparseable).toMatch(/block scalar/);
    });

    it('flags tab indentation', () => {
      expect(readYamlLite('a:\n\tb: 1\n').unparseable).toMatch(/tab indentation/);
    });

    it('flags a multi-document stream', () => {
      expect(readYamlLite('---\na: 1\n').unparseable).toMatch(/multi-document/);
    });

    it('leaves unparseable null on input it fully handles', () => {
      expect(readYamlLite('pnpm:\n  minimumReleaseAge: 4320\n').unparseable).toBeNull();
    });
  });
});
