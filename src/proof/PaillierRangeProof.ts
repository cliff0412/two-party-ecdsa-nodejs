import BN from 'bn.js';
import { CryptoException } from '../exception/CryptoException'
class ZTuple {
    a: BN;
    b: BN;
    c: BN;
    d: BN;

    constructor(a: BN, b: BN, c: BN, d: BN) {
        this.a = a;
        this.b = b;
        this.c = c;
        this.d = d;
    }

    // constructor( a: BN,  b: BN,  c: BN) {
    //     this.a = a;
    //     this.b = b;
    //     this.c = c;
    //     this.d = null;
    // }

    /**
     * Getter method for property <tt>a</tt>.
     *
     * @return property value of a
     */
    public getA(): BN {
        return this.a;
    }

    /**
     * Getter method for property <tt>b</tt>.
     *
     * @return property value of b
     */
    public getB(): BN {
        return this.b;
    }

    /**
     * Getter method for property <tt>c</tt>.
     *
     * @return property value of c
     */
    public getC(): BN {
        return this.c;
    }

    /**
     * Getter method for property <tt>d</tt>.
     *
     * @return property value of d
     */
    public getD(): BN {
        return this.d;
    }

    // public Object toJSON() {

    //     JSONObject obj = new JSONObject();
    //     obj.put("a", Hex.toHexString(a.toByteArray()));
    //     obj.put("b", Hex.toHexString(b.toByteArray()));
    //     obj.put("c", Hex.toHexString(c.toByteArray()));
    //     obj.put("d", Hex.toHexString(d.toByteArray()));
    //     return obj;
    // }

}

export class PaillierRangeProof {
    public static SECURITY_PARAM: number = 40;
    private c1: BN[];
    private c2: BN[];
    private z: ZTuple[];



    public PaillierRangeProof(c1: BN[], c2: BN[], z: ZTuple[]) {
        if (c1 == null || c2 == null || z == null) {
            throw Error(CryptoException.NULL_INPUT);
        }
        if (c1.length != PaillierRangeProof.SECURITY_PARAM || c2.length != PaillierRangeProof.SECURITY_PARAM || z.length != PaillierRangeProof.SECURITY_PARAM) {
            throw Error(CryptoException.INCONSISTENT_INPUTS);
        }

        this.c1 = c1;
        this.c2 = c2;
        this.z = z;
    }

    public getC1(): BN[] {
        return this.c1;
    }

    public getC2(): BN[] {
        return this.c2;
    }

    public getZ(): ZTuple[] {
        return this.z;
    }
}