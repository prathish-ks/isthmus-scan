/**
 * A deliberately tiny, indentation-only YAML reader.
 *
 * Why not a real YAML library: this package ships zero runtime dependencies
 * on purpose — the README's claim is that you can read the whole tool before
 * running it, which stops being true the moment `npm i` pulls a parser in.
 * And the one question this file exists to answer does not need a full
 * parser: *is this key at the top level, or nested under another one?* That
 * distinction is pure indentation.
 *
 * What it handles: block mappings, block sequences, `#` comments, quoted
 * scalars, and nesting by indentation.
 *
 * What it does NOT handle, and reports rather than guesses: flow style
 * (`{a: 1}`, `[a, b]`), anchors and aliases, multi-document streams, block
 * scalars (`|`, `>`), and tabs for indentation. Every consumer must treat
 * `unparseable` as "I could not tell", never as "absent" — a supply-chain
 * gate reported as missing because the reader gave up would be exactly the
 * kind of confidently-wrong answer this tool exists to avoid.
 */

export interface YamlEntry {
  /** The key, for a mapping entry. `null` for a sequence item. */
  key: string | null;
  /** The raw scalar after `:` (or after `-`), comment-stripped and unquoted. Empty when the value is a nested block. */
  value: string;
  /** Number of leading spaces. */
  indent: number;
  /** Keys of the enclosing mappings, outermost first. Empty for a top-level entry. */
  path: string[];
  /** 1-based source line, for messages a human has to act on. */
  line: number;
}

export interface YamlLiteResult {
  entries: YamlEntry[];
  /** Set when a construct this reader does not handle was found. Consumers must not treat a key as absent in this case. */
  unparseable: string | null;
}

/** Strips a trailing `#` comment, respecting single and double quotes. */
function stripComment(line: string): string {
  let quote: string | null = null;
  for (let i = 0; i < line.length; i++) {
    const ch = line[i];
    if (quote) {
      if (ch === quote) quote = null;
      continue;
    }
    if (ch === '"' || ch === "'") {
      quote = ch;
      continue;
    }
    // A `#` only opens a comment at the start of a line or after whitespace.
    if (ch === '#' && (i === 0 || /\s/.test(line[i - 1]))) return line.slice(0, i);
  }
  return line;
}

function unquote(value: string): string {
  const v = value.trim();
  if (v.length >= 2 && ((v.startsWith('"') && v.endsWith('"')) || (v.startsWith("'") && v.endsWith("'")))) {
    return v.slice(1, -1);
  }
  return v;
}

export function readYamlLite(source: string): YamlLiteResult {
  const entries: YamlEntry[] = [];
  let unparseable: string | null = null;

  // Stack of enclosing mapping keys and the indent they were declared at.
  const stack: { indent: number; key: string }[] = [];

  const rawLines = source.split('\n');
  for (let i = 0; i < rawLines.length; i++) {
    const raw = rawLines[i];
    const lineNo = i + 1;

    if (/^\s*$/.test(raw)) continue;
    if (/^\s*#/.test(raw)) continue;

    if (raw.startsWith('---') || raw.startsWith('...')) {
      unparseable ??= `multi-document stream at line ${lineNo}`;
      continue;
    }
    if (/^\t| \t/.test(raw)) {
      unparseable ??= `tab indentation at line ${lineNo}`;
      continue;
    }

    const content = stripComment(raw);
    if (/^\s*$/.test(content)) continue;

    const indent = content.length - content.trimStart().length;
    const trimmed = content.trim();

    // Unwind to the enclosing mapping for this indent.
    while (stack.length > 0 && stack[stack.length - 1].indent >= indent) stack.pop();
    const path = stack.map((s) => s.key);

    const seqMatch = trimmed.match(/^-\s*(.*)$/);
    if (seqMatch) {
      const value = seqMatch[1];
      if (value.startsWith('{') || value.startsWith('[')) {
        unparseable ??= `flow-style value at line ${lineNo}`;
        continue;
      }
      entries.push({ key: null, value: unquote(value), indent, path, line: lineNo });
      continue;
    }

    const mapMatch = trimmed.match(/^([A-Za-z0-9_.@/-]+)\s*:\s*(.*)$/);
    if (mapMatch) {
      const [, key, rawValue] = mapMatch;
      if (rawValue.startsWith('{') || rawValue.startsWith('[')) {
        unparseable ??= `flow-style value for "${key}" at line ${lineNo}`;
        continue;
      }
      if (rawValue === '|' || rawValue === '>' || rawValue.startsWith('|') || rawValue.startsWith('>')) {
        unparseable ??= `block scalar for "${key}" at line ${lineNo}`;
        continue;
      }
      if (rawValue.startsWith('&') || rawValue.startsWith('*')) {
        unparseable ??= `anchor or alias for "${key}" at line ${lineNo}`;
        continue;
      }
      entries.push({ key, value: unquote(rawValue), indent, path, line: lineNo });
      // A key with no inline value opens a nested block.
      if (rawValue.trim() === '') stack.push({ indent, key });
      continue;
    }

    unparseable ??= `unrecognized syntax at line ${lineNo}`;
  }

  return { entries, unparseable };
}

/** Every entry for `key`, at any nesting depth. */
export function findKey(result: YamlLiteResult, key: string): YamlEntry[] {
  return result.entries.filter((e) => e.key === key);
}

/** The sequence items belonging to the block opened by `entry`. */
export function sequenceUnder(result: YamlLiteResult, entry: YamlEntry): string[] {
  return result.entries
    .filter((e) => e.key === null && e.indent > entry.indent && pathStartsWith(e.path, [...entry.path, entry.key ?? '']))
    .map((e) => e.value);
}

/** The mapping entries belonging to the block opened by `entry`. */
export function mappingUnder(result: YamlLiteResult, entry: YamlEntry): YamlEntry[] {
  return result.entries.filter(
    (e) => e.key !== null && e.indent > entry.indent && pathStartsWith(e.path, [...entry.path, entry.key ?? '']),
  );
}

function pathStartsWith(path: string[], prefix: string[]): boolean {
  if (path.length < prefix.length) return false;
  return prefix.every((p, i) => path[i] === p);
}
