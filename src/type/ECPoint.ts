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

export interface Signature {
    r: BN;
    s: BN;
    recovery?: number;
}

export interface SignatureOnChain {
    r: BN;
    s: BN;
    v: number;
}


interface P1KeyGenContext {

    paillierPrivateKey: {
        p: BN;
        q: BN;
    },
    ecdsaPrivateKeyShare: BN;
}

interface P2KeyGenContext {
    paillierPublicKey: {
        N: BN;
    };
    cKey: BN;
    ecdsaPrivateKeyShare: BN;
}

export interface KeyGenContext {
    p1: P1KeyGenContext;
    p2: P2KeyGenContext;
    x: BN;
    Q: ECPoint;
}

export interface KeyGenContextVO {
    addressFromPoint: string;
    addressFromX: string;
    x: string;
    p1: {
        x1: string;
        paillierPrivateKeyP: string;
        paillierPrivateKeyQ: string
    },
    p2: {
        paillierPublicKeyN: string;
        cKey: string;
        x2: string;
    }
}