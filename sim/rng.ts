/** Deterministic PRNG for the soak / fuzz harness.
 *
 *  Seeded (mulberry32) so every run — local or CI — is byte-reproducible: a
 *  failure always reproduces from its seed. Never used for anything security
 *  sensitive; production key material and IDs come from a CSPRNG (see ids.ts /
 *  envelope.ts). This is test infrastructure only.
 */
export class Rng {
  private s: number;
  constructor(seed: number) {
    this.s = (seed >>> 0) || 0x9e3779b9;
  }
  /** Uniform in [0, 1). */
  next(): number {
    this.s = (this.s + 0x6d2b79f5) >>> 0;
    let t = this.s;
    t = Math.imul(t ^ (t >>> 15), t | 1);
    t ^= t + Math.imul(t ^ (t >>> 7), t | 61);
    return ((t ^ (t >>> 14)) >>> 0) / 4294967296;
  }
  /** Integer in [min, max]. */
  int(min: number, max: number): number {
    return min + Math.floor(this.next() * (max - min + 1));
  }
  bool(p = 0.5): boolean {
    return this.next() < p;
  }
  pick<T>(arr: readonly T[]): T {
    return arr[this.int(0, arr.length - 1)]!;
  }
  /** A random subset of size k (distinct, order-shuffled). */
  sample<T>(arr: readonly T[], k: number): T[] {
    return this.shuffle([...arr]).slice(0, Math.min(k, arr.length));
  }
  shuffle<T>(arr: T[]): T[] {
    const a = [...arr];
    for (let i = a.length - 1; i > 0; i--) {
      const j = this.int(0, i);
      [a[i], a[j]] = [a[j]!, a[i]!];
    }
    return a;
  }
  /** Lowercase alphanumeric token of length len (matches [a-z0-9]). */
  token(len: number): string {
    const ALPH = "abcdefghijklmnopqrstuvwxyz0123456789";
    let out = "";
    for (let i = 0; i < len; i++) out += ALPH[this.int(0, ALPH.length - 1)];
    return out;
  }
  /** n deterministic bytes — used only for test key seeds. */
  bytes(n: number): Uint8Array {
    const b = new Uint8Array(n);
    for (let i = 0; i < n; i++) b[i] = this.int(0, 255);
    return b;
  }
}
