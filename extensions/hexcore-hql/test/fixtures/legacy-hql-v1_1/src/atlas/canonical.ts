import { createHash } from 'crypto';

function canonicalizeValue(value: unknown, path: string): string {
  if (value === null) {
    return 'null';
  }

  switch (typeof value) {
    case 'string':
    case 'boolean':
      return JSON.stringify(value);
    case 'number':
      if (!Number.isFinite(value)) {
        throw new Error(`Non-finite number at ${path}`);
      }
      return Object.is(value, -0) ? '0' : JSON.stringify(value);
    case 'object':
      if (Array.isArray(value)) {
        return `[${value.map((entry, index) => canonicalizeValue(entry, `${path}[${index}]`)).join(',')}]`;
      }
      if (Object.getPrototypeOf(value) !== Object.prototype) {
        throw new Error(`Only plain JSON objects are canonicalizable at ${path}`);
      }
      return `{${Object.keys(value as Record<string, unknown>)
        .sort()
        .map(key => {
          const entry = (value as Record<string, unknown>)[key];
          if (entry === undefined) {
            throw new Error(`Undefined value at ${path}.${key}`);
          }
          return `${JSON.stringify(key)}:${canonicalizeValue(entry, `${path}.${key}`)}`;
        })
        .join(',')}}`;
    default:
      throw new Error(`Unsupported ${typeof value} at ${path}`);
  }
}

/** Stable JSON with lexicographically sorted object keys and preserved array order. */
export function canonicalJson(value: unknown): string {
  return canonicalizeValue(value, '$');
}

export function sha256Hex(data: string | Buffer): string {
  return createHash('sha256').update(data).digest('hex');
}

export function canonicalSha256(value: unknown): string {
  return sha256Hex(canonicalJson(value));
}
