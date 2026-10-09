// Token buckets, per device, held in Durable Object memory.
//
// In-memory state is lost when the object hibernates or is evicted; that only
// happens after it has been idle for several seconds, during which a bucket
// refills anyway. Persisting buckets would cost one storage write per request.

export interface BucketSpec {
  /** Burst size. */
  capacity: number;
  /** Milliseconds per refilled token. */
  refillMs: number;
}

/** §6.4: 60 wakes per minute per device, burst 20. */
export const WAKE_LIMIT: BucketSpec = { capacity: 20, refillMs: 1000 };
/** Architecture §5: appends are rate-limited per device (not in the protocol; 10/min, burst 10). */
export const APPEND_LIMIT: BucketSpec = { capacity: 10, refillMs: 6000 };
/** Other WebSocket requests (presence, log-get): 60/min, burst 30. */
export const MISC_LIMIT: BucketSpec = { capacity: 30, refillMs: 1000 };

export class TokenBucket {
  private tokens: number;
  private last: number;

  constructor(
    private readonly spec: BucketSpec,
    now: number,
  ) {
    this.tokens = spec.capacity;
    this.last = now;
  }

  take(now: number): boolean {
    const elapsed = Math.max(0, now - this.last);
    this.tokens = Math.min(this.spec.capacity, this.tokens + elapsed / this.spec.refillMs);
    this.last = now;
    if (this.tokens < 1) return false;
    this.tokens -= 1;
    return true;
  }
}

export class Limiter {
  private readonly buckets = new Map<string, TokenBucket>();

  constructor(private readonly spec: BucketSpec) {}

  take(key: string, now: number): boolean {
    let b = this.buckets.get(key);
    if (b === undefined) {
      b = new TokenBucket(this.spec, now);
      this.buckets.set(key, b);
    }
    return b.take(now);
  }
}
