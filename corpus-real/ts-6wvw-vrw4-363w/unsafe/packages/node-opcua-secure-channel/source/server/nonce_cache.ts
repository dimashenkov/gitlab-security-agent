











export type Nonce = Buffer;




export function isEmptyNonce(nonce: Nonce): boolean {
    const countZero = nonce.reduce(
        (accumulator: number, currentValue: number) => accumulator + (currentValue === 0 ? 1 : 0),
        0
    );
    return countZero === nonce.length;
}


const DEFAULT_TTL_MS = 4 * 3_600_000;

const DEFAULT_MAX_SIZE = 50_000;

let g_ttlMs = DEFAULT_TTL_MS;
let g_maxSize = DEFAULT_MAX_SIZE;




const g_alreadyUsedNonce = new Map<string, number>();





function _evict(): void {
    const cutoff = Date.now() - g_ttlMs;


    for (const [key, timestamp] of g_alreadyUsedNonce) {
        if (timestamp <= cutoff) {
            g_alreadyUsedNonce.delete(key);
        }
    }


    if (g_alreadyUsedNonce.size > g_maxSize) {
        const excess = g_alreadyUsedNonce.size - g_maxSize;
        const iter = g_alreadyUsedNonce.keys();
        for (let i = 0; i < excess; i++) {
            const { value, done } = iter.next();
            if (done) break;
            g_alreadyUsedNonce.delete(value);
        }
    }
}

export function nonceAlreadyBeenUsed(nonce?: Nonce): boolean {
    if (!nonce || isEmptyNonce(nonce)) {
        return false;
    }

    _evict();

    const hash = nonce.toString("base64");
    if (g_alreadyUsedNonce.has(hash)) {
        return true;
    }
    g_alreadyUsedNonce.set(hash, Date.now());
    _evict();
    return false;
}









export function _getNonceStore(): Map<string, number> {
    return g_alreadyUsedNonce;
}





export function _setNonceCacheParameters(ttlMs?: number, maxSize?: number): void {
    g_ttlMs = ttlMs ?? DEFAULT_TTL_MS;
    g_maxSize = maxSize ?? DEFAULT_MAX_SIZE;
}
