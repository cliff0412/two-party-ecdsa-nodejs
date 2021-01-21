import BN from 'bn.js';

export interface ECPoint {
    // curve: base;
    type: string;    // affine
    // precomputed: PrecomputedValues | null;

    // constructor(curve: base, type: string);

    encode(enc: "hex", compact: boolean): string;
    encode(enc: "array" | undefined, compact: boolean): number[];
    encodeCompressed(enc: "hex"): string;
    encodeCompressed(enc?: "array"): number[];
    validate(): boolean;
    precompute(power: number): ECPoint;
    dblp(k: number): ECPoint;
    inspect(): string;
    isInfinity(): boolean;
    add(p: ECPoint): ECPoint;
    mul(k: BN): ECPoint;
    dbl(): ECPoint;
    getX(): BN;
    getY(): BN;
    eq(p: ECPoint): boolean;
    neg(): ECPoint;
}