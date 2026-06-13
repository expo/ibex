export type LocaleDirection = 'ltr' | 'rtl';

export interface ParsedLocaleTag {
  language: string;
  script?: string;
  region?: string;
}

const RTL_SCRIPT_SUBTAGS = new Set([
  'adlm',
  'arab',
  'hebr',
  'mand',
  'nkoo',
  'rohg',
  'samr',
  'syrc',
  'thaa',
]);

const RTL_LANGUAGE_SUBTAGS = new Set([
  'ae',
  'aeb',
  'ar',
  'arc',
  'arq',
  'ars',
  'ary',
  'arz',
  'azb',
  'bal',
  'bcc',
  'bqi',
  'ckb',
  'dv',
  'fa',
  'glk',
  'he',
  'iw',
  'ks',
  'khw',
  'lrc',
  'mzn',
  'nqo',
  'pnb',
  'ps',
  'sd',
  'syr',
  'ug',
  'ur',
  'yi',
]);

export function canonicalizeLocaleTag(tag: string): string {
  const input = tag.trim();
  if (input.length === 0) {
    return input;
  }

  if (typeof Intl === 'object' && Intl && typeof Intl.getCanonicalLocales === 'function') {
    try {
      const [canonical] = Intl.getCanonicalLocales(input);
      if (typeof canonical === 'string' && canonical.length > 0) {
        return canonical;
      }
    } catch {
      // Fall through to the local canonicalizer.
    }
  }

  const parts = input.split('-');
  if (parts.length > 0) {
    parts[0] = parts[0]!.toLowerCase();
  }

  for (let index = 1; index < parts.length; index += 1) {
    const part = parts[index];
    if (!part) {
      continue;
    }

    if (part.length === 4) {
      parts[index] = part[0]!.toUpperCase() + part.slice(1).toLowerCase();
      continue;
    }

    if (part.length === 2 || (part.length === 3 && /^[0-9A-Za-z]{3}$/.test(part))) {
      parts[index] = part.toUpperCase();
      continue;
    }

    parts[index] = part.toLowerCase();
  }

  return parts.join('-');
}

export function parseLocaleTag(tag: string): ParsedLocaleTag {
  const canonical = canonicalizeLocaleTag(tag);
  const parts = canonical.split('-').filter(Boolean);
  const parsed: ParsedLocaleTag = {
    language: parts[0]?.toLowerCase() || 'en',
  };

  for (const part of parts.slice(1)) {
    if (part.length === 4 && parsed.script === undefined) {
      parsed.script = part;
      continue;
    }

    if ((part.length === 2 || part.length === 3) && parsed.region === undefined) {
      parsed.region = part;
      continue;
    }

    if (part.length === 1) {
      break;
    }
  }

  return parsed;
}

export function directionForLocaleTag(tag: string): LocaleDirection {
  const parsed = parseLocaleTag(tag);
  if (parsed.script && RTL_SCRIPT_SUBTAGS.has(parsed.script.toLowerCase())) {
    return 'rtl';
  }

  return RTL_LANGUAGE_SUBTAGS.has(parsed.language) ? 'rtl' : 'ltr';
}

function isAsciiNeutral(codePoint: number): boolean {
  return (
    codePoint <= 0x20 ||
    (codePoint >= 0x30 && codePoint <= 0x39) ||
    (codePoint >= 0x21 && codePoint <= 0x2f) ||
    (codePoint >= 0x3a && codePoint <= 0x40) ||
    (codePoint >= 0x5b && codePoint <= 0x60) ||
    (codePoint >= 0x7b && codePoint <= 0x7e)
  );
}

function isRtlCodePoint(codePoint: number): boolean {
  return (
    (codePoint >= 0x0590 && codePoint <= 0x08ff) ||
    (codePoint >= 0xfb1d && codePoint <= 0xfdff) ||
    (codePoint >= 0xfe70 && codePoint <= 0xfefc) ||
    (codePoint >= 0x10800 && codePoint <= 0x10fff) ||
    (codePoint >= 0x1e800 && codePoint <= 0x1eeff)
  );
}

function isNeutralCodePoint(codePoint: number): boolean {
  return (
    isAsciiNeutral(codePoint) ||
    (codePoint >= 0x0660 && codePoint <= 0x0669) ||
    (codePoint >= 0x06f0 && codePoint <= 0x06f9) ||
    (codePoint >= 0x2000 && codePoint <= 0x206f) ||
    (codePoint >= 0x20a0 && codePoint <= 0x20cf) ||
    (codePoint >= 0x2190 && codePoint <= 0x21ff) ||
    (codePoint >= 0x2460 && codePoint <= 0x27ff) ||
    (codePoint >= 0x1f000 && codePoint <= 0x1faff)
  );
}

export function detectTextDirection(
  text: string | undefined,
  fallback: LocaleDirection,
): LocaleDirection {
  if (typeof text !== 'string' || text.length === 0) {
    return fallback;
  }

  for (const char of text) {
    const codePoint = char.codePointAt(0);
    if (codePoint === undefined) {
      continue;
    }

    if (isNeutralCodePoint(codePoint)) {
      continue;
    }

    return isRtlCodePoint(codePoint) ? 'rtl' : 'ltr';
  }

  return fallback;
}
