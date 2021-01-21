import BN from 'bn.js';

import { ECDlogProof } from './ECDlogProof';
import { ECPoint } from '../type';
import { CryptoException } from '../exception/CryptoException';
import { CryptoConsants } from '../common/CryptoConstants';

import * as elliptic from 'elliptic';
import * as random from '../util/random';
import crypto from 'crypto';



export class ProofUtils {

    public static ec = new elliptic.ec('secp256k1');

    /**
     * Generates a elliptic curve discrete logarithm proof.
     * @param G the base point of the curve
     * @param P the public point
     * @param x the private integer, such that P=[x]G
     * @return an ECDlogProof
     */
    public static generateECDlogProof(G: ECPoint, P: ECPoint, x: BN): ECDlogProof {
        if (G == null || P == null || x == null) {
            throw new Error(CryptoException.NULL_INPUT);
        }
        if (G.isInfinity()) {
            throw new Error(CryptoException.INFINITY_POINT);
        }


        let n: BN = this.ec.curve.n;

        let k: BN = random.randBetween(CryptoConsants.ONE, n.sub(CryptoConsants.ONE));
        let X: ECPoint = G.mul(k);

        // e = Hash(G, P, X) mod n
        let e: BN = this.computeChallenge(n, G, P, X);
        let z: BN = k.add(e.mul(x)).mod(n);

        return new ECDlogProof(P, X, z);
    }

    /**
    * Computes a challenge value modulo a modulus from elliptic curve points.
    * @param m the modulus
    * @param points the elliptic curve points
    * @return a challenge value modulo m
    */
    private static computeChallenge(m: BN, ...points: ECPoint[]): BN {

        let md = crypto.createHash('sha256')
        // MessageDigest md = MessageDigest.getInstance("SHA-256");
        for (let point of points) {
            if (point == null) {
                throw new Error(CryptoException.NULL_INPUT);
            }
            // TODO: encodeCompressed to be tested
            md.update(point.encodeCompressed('hex'));
        }
        let hash: Buffer = md.digest();
        return this.hashToInt(hash, m);
    }

    /**
    * Converts a hash value to integer modulo a modulus.
    * @param hash the hash value
    * @param m the modulus
    * @return an integer modulo m
    */
    private static hashToInt(hash: Buffer, m: BN): BN {
        if (hash == null || m == null) {
            throw new Error(CryptoException.NULL_INPUT);
        }
        if (m.isNeg()) {
            throw new Error(CryptoException.PARAMETER_TOO_SMALL);
        }

        let t: BN;
        try {
            t = new BN(hash);
        } catch (e) {
            throw new Error(CryptoException.INVALID_LENGTH);
        }

        return t.mod(m);
    }
}