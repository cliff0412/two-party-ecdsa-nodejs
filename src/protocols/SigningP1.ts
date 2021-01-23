import BN from 'bn.js';

import { PaillierPrivateKey, Paillier } from '../paillier'
import { SigningContextP1 } from './SigningContextP1';
import { CryptoConsants } from '../common/CryptoConstants'
import { CryptoException } from "../exception/CryptoException";
import { random, ellipticUtil } from '../util'
import { ECPoint } from '../type'


export class SigningP1 {
    /** 
     * ECDSA private key share
     */
    private ecdsaPrivateKeyShare: BN;
    /**
     * ECDSA public key
     */
    private ecdsaPublicKey: ECPoint;
    /**
     * Paillier private key
     */
    private paillierPrivateKey: PaillierPrivateKey;

    public constructor(context: SigningContextP1) {
        if (context == null
            || context.getPaillierPrivateKey() == null
            || context.getEcdsaPrivateKeyShare() == null
            || context.getEcdsaPublicKey() == null) {
            throw new Error(CryptoException.NULL_INPUT);
        }
        this.ecdsaPrivateKeyShare = context.getEcdsaPrivateKeyShare();
        this.ecdsaPublicKey = context.getEcdsaPublicKey();
        this.paillierPrivateKey = context.getPaillierPrivateKey();
    }

    public generatePrivateRandomShare(): BN {
        let n = CryptoConsants.SECP256_CURVE_N;
        return random.randBetween(CryptoConsants.ONE, n.sub(CryptoConsants.ONE));
    }

    public computePublicRandomShare(privateRandomShare: BN): ECPoint {
        return CryptoConsants.SECP256_CURVE_G.mul(privateRandomShare);
    }

    public computeSignature(z: BN, p2PublicRandomShare: ECPoint, c3: BN,
        privateRandomShare: BN): BN[] {
        if (z == null || p2PublicRandomShare == null || c3 == null) {
            throw new Error(CryptoException.NULL_INPUT);
        }
        if (z.lt(CryptoConsants.ZERO) || z.bitLength() > CryptoConsants.SECP256_CURVE_N.bitLength()) {
            throw new Error(CryptoException.PARAMETER_OUT_OF_RANGE);
        }

        let n = CryptoConsants.SECP256_CURVE_N;
        let R = p2PublicRandomShare.mul(privateRandomShare);

        //BigInteger r = R.normalize().getXCoord().toBigInteger().mod(n);
        let r = R.getX().mod(n)

        let s = Paillier.decrypt(this.paillierPrivateKey, c3);

        s = s.mul(privateRandomShare.toRed(BN.red(n)).redInvm()).mod(n);
        if (s.gt(n.shrn(1))) {
            s = n.sub(s);
        }

        if (ellipticUtil.verifySig(
            z,
            r,
            s,
            Buffer.from(this.ecdsaPublicKey.encodeCompressed("hex"), "hex")
        )) {
            return [r, s];
        } else {
            throw new Error(CryptoException.VERIFY_SIGNATURE_FAILED);
        }
    }

    public getEcdsaPrivateKeyShare() {
        return this.ecdsaPrivateKeyShare
    }

    // private  verifySignature( r: BN,  s: BN,  z: BN) : boolean {
    //     let n = CryptoConsants.SECP256_CURVE_N;


    //     let sInv =  s.toRed(BN.red(n)).redInvm();
    //     let u1 = z.mul(sInv).mod(n);
    //     let u2 = r.mul(sInv).mod(n);

    //     ECPoint sum = ECAlgorithms.sumOfTwoMultiplies(domainParams.getEcSpec().getG(), u1, ecdsaPublicKey, u2);
    //     if (sum.isInfinity()) {
    //         return false;
    //     }

    //     return r.equals(sum.normalize().getXCoord().toBigInteger().mod(n));
    // }


}