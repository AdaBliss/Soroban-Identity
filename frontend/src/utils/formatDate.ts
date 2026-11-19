import type React from 'react';
import { format as formatFns } from 'date-fns';
import { enUS, es, fr, zhCN } from 'date-fns/locale';
import i18n from '../i18n';

const DATE_FNS_LOCALES: Record<string, typeof enUS> = {
  en: enUS,
  es,
  fr,
  zh: zhCN,
};

function getDateFnsLocale() {
  const currentLang = i18n.language ? i18n.language.split('-')[0] : 'en';
  return DATE_FNS_LOCALES[currentLang] || enUS;
}

const MAX_DATE_MS = 8_640_000_000_000_000; // ECMAScript max Date millisecond value
const MAX_DATE_SECS = 8_640_000_000_000;

// Stellar ledgers close at a target of one every 5 seconds.
export const STELLAR_LEDGER_CLOSE_SECONDS = 5;
// Unix timestamp (seconds) of the Stellar genesis ledger (ledger sequence 1).
export const STELLAR_GENESIS_UNIX_SECONDS = 1_600_000_000;

/**
 * Convert a Stellar ledger sequence to a UTC Unix timestamp (in seconds).
 *
 * Uses the accurate 5-second-per-ledger close time so the computed expiry
 * matches the on-chain value (the previous constant was off by ~5s/ledger).
 * If the caller has the actual ledger close time available it should be
 * preferred; this helper is the deterministic fallback.
 */
export function ledgerSequenceToUnixSeconds(ledgerSequence: number | bigint | string): number {
  const seq = typeof ledgerSequence === 'bigint' ? Number(ledgerSequence) : Number(ledgerSequence);
  if (!Number.isFinite(seq) || seq <= 0) return 0;
  return STELLAR_GENESIS_UNIX_SECONDS + (Math.floor(seq) - 1) * STELLAR_LEDGER_CLOSE_SECONDS;
}

/**
 * Convert a Stellar ledger sequence to a UTC Date.
 */
export function ledgerSequenceToDate(ledgerSequence: number | bigint | string): Date {
  return new Date(ledgerSequenceToUnixSeconds(ledgerSequence) * 1000);
}

export function normalizeUnixTimestamp(value: number | bigint | string): number {
  const num = typeof value === 'bigint' ? Number(value) : typeof value === 'string' ? Number(value) : value;
  if (!Number.isFinite(num) || num <= 0) return 0;
  // Unsigned 32-bit wrap-around recovery if a negative 32-bit signed int was produced
  if (num < 0) {
    return num + 0x100000000;
  }
  return num;
}

export function formatDate(value: string | number | bigint): string {
  if (typeof value === 'string' && !/^\d+$/.test(value.trim())) {
    const date = new Date(value);
    return isNaN(date.getTime()) ? String(value) : formatFns(date, 'PPP', { locale: getDateFnsLocale() });
  }
  const unix = normalizeUnixTimestamp(value);
  if (unix >= MAX_DATE_SECS) {
    return 'Far future (max timestamp)';
  }
  const ms = Math.min(unix * 1000, MAX_DATE_MS);
  const date = new Date(ms);
  if (Number.isNaN(date.getTime())) {
    return typeof value === 'number' ? `Unix ${normalizeUnixTimestamp(value)}` : String(value);
  }
  return formatFns(date, 'PPP', { locale: getDateFnsLocale() });
}

export function formatTimestamp(unix: number | bigint): string {
  const normalized = normalizeUnixTimestamp(unix);
  if (normalized === 0) return 'No expiry';
  if (normalized >= MAX_DATE_SECS) return 'Far future (max timestamp)';
  const date = new Date(Math.min(normalized * 1000, MAX_DATE_MS));
  return formatFns(date, 'PPpp', { locale: getDateFnsLocale() });
}

export function getExpiryStyle(unix: number | bigint): React.CSSProperties {
  const normalized = normalizeUnixTimestamp(unix);
  if (normalized === 0) return { color: 'var(--text-muted)' };
  if (normalized >= MAX_DATE_SECS) return {};
  const diffMs = normalized * 1000 - Date.now();
  if (diffMs < 0) return { color: 'var(--text-muted)' };
  if (diffMs < 7 * 24 * 60 * 60 * 1000) return { color: 'var(--warning)', fontWeight: 600 };
  return {};
}
