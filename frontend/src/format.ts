export function bytes(n: number): string {
  if (n < 1024) return `${n} B`;
  if (n < 1024 * 1024) return `${(n / 1024).toFixed(1)} KB`;
  if (n < 1024 * 1024 * 1024) return `${(n / 1024 / 1024).toFixed(2)} MB`;
  return `${(n / 1024 / 1024 / 1024).toFixed(2)} GB`;
}

export function nicenum(n: number): string {
  return n.toLocaleString();
}

export function timeFmt(epochSec: number): string {
  const d = new Date(epochSec * 1000);
  return d.toLocaleTimeString([], { hour12: false });
}
