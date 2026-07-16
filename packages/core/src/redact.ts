/**
 * Secret values never leave the scanner intact: findings carry only the
 * first 8 characters plus the total length.
 */
export function redactSecret(value: string): string {
  return `${value.slice(0, 8)}…(${value.length} chars)`;
}
