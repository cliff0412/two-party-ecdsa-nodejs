import BN from 'bn.js';
import * as bigintCryptoUtils from 'bigint-crypto-utils'

import { CryptoException } from "../exception/CryptoException";

import PaillierPublicKey from './PaillierPublicKey';
import PaillierPrivateKey from './PaillierPrivateKey';
import * as util from '../util/util';
import { CryptoConsants } from '../common/CryptoConstants';

export default class Paillier {
    public static ONE = new BN("1", 10);

    /**
     * Encrypts plaintext under Paillier public key.
     * @param publicKey the Paillier public key
     * @param m the plaintext
     * @return the ciphertext of m
     */
    public static encrypt(publicKey: PaillierPublicKey, m: BN): BN {
        if (publicKey == null || m == null) {
            throw new Error(CryptoException.NULL_INPUT);
        }



        let r: bigint;
        let rInBN: BN;
        do {
            r = bigintCryptoUtils.randBetween(
                util.bnToBigInt(publicKey.getN().sub(this.ONE)),
                util.bnToBigInt(this.ONE));
            rInBN = util.bigIntToBN(r);
        } while (
            // bigintCryptoUtils.gcd(r, ) != 1n
            !rInBN.gcd(publicKey.getN()).eq(this.ONE)
        );

        return this.encryptWithRandom(publicKey, m, rInBN);


    }

    /**
     * Encrypts plaintext with randomness under Paillier public key.
     * @param publicKey the Paillier public key
     * @param m the plaintext
     * @param r the randomness
     * @return the ciphertext of m: (1+N)^m * r^N mod N^2
     */
    public static encryptWithRandom(publicKey: PaillierPublicKey, m: BN, r: BN): BN {
        if (publicKey == null || m == null || r == null) {
            throw new Error(CryptoException.NULL_INPUT);
        }


        if (m.gte(publicKey.getN()) || m.isNeg()) {

            throw new Error(CryptoException.PARAMETER_OUT_OF_RANGE);
        }


        console.log("gcd", r.gcd(publicKey.getN()).toString())
        console.log("is equal one", r.gcd(publicKey.getN()))
        if (r.isNeg() || r.gte(publicKey.getN()) || !r.gcd(publicKey.getN()).eq(this.ONE)) {

            throw new Error(CryptoException.INVALID_RANDOMNESS);
        }

        // console.log("-------start----")
        let N = publicKey.getN();
        let N2 = N.sqr();
        let c = m.mul(N).add(this.ONE);



        let red = BN.red(N2);
        let rRed = r.toRed(red);
        console.log(rRed.redPow(N))

        c = c.mul(rRed.redPow(N)).mod(N2);
        // console.log("-------end----")
        return c;
    }

    /**
    * Decrypts ciphertext under Paillier private key.
    * @param privateKey the Paillier private key
    * @param c the ciphertext
    * @return the plaintext
    */
    public static decrypt(privateKey: PaillierPrivateKey, c: BN): BN {
        if (privateKey == null || c == null) {
            throw new Error(CryptoException.NULL_INPUT);
        }

        let N: BN = privateKey.getN();
        let N2: BN = privateKey.getnSquare();
        let p2: BN = privateKey.getpSquare();
        let q2: BN = privateKey.getqSquare();
        let p2Inv: BN = privateKey.getpSquareInv();
        let q2Inv: BN = privateKey.getqSquareInv();
        let lambda: BN = privateKey.getLambda();

        let p2Red = BN.red(p2);
        let q2Red = BN.red(q2);

        let cp: BN = c.mod(p2).toRed(p2Red).redPow(lambda);
        let cq: BN = c.mod(q2).toRed(q2Red).redPow(lambda);


        let cn: BN = cp.mul(q2).mul(q2Inv).mod(N2);
        cn = cn.add(cq.mul(p2).mul(p2Inv).mod(N2)).mod(N2);

        return cn.sub(this.ONE).div(N).mul(privateKey.getLambdaInv()).mod(N);
    }

    /**
     * Homomorphic addition of two Paillier ciphertexts.
     * @param publicKey the Paillier public key
     * @param c1 the first ciphertext
     * @param c2 the second ciphertext
     * @return a new ciphertext encrypts the addition of the two plaintexts in the ciphertexts
     */
    public static add(publicKey: PaillierPublicKey, c1: BN, c2: BN): BN {
        if (publicKey == null || c1 == null || c2 == null) {
            throw new Error(CryptoException.NULL_INPUT);
        }

        return c1.mul(c2).mod(publicKey.getnSquare());
    }

    /**
     * Homomorphic subtraction of two Paillier ciphertexts.
     * @param publicKey the Paillier public key
     * @param c1 the first ciphertext
     * @param c2 the second ciphertext
     * @return a new ciphertext encrypts the subtraction of the two plaintexts in the ciphertexts
     */
    public static subtract(publicKey: PaillierPublicKey, c1: BN, c2: BN): BN {
        if (publicKey == null || c1 == null || c2 == null) {
            throw new Error(CryptoException.NULL_INPUT);
        }

        let nSquareRed = BN.red(publicKey.getnSquare());

        let t: BN = c2.toRed(nSquareRed).redInvm();
        return c1.mul(t).mod(publicKey.getnSquare());
    }

    /**
    * Homomorphic subtraction of a Paillier ciphertext and a Paillier plaintext.
    * @param publicKey the Paillier public key
    * @param c the ciphertext
    * @param m the plaintext
    * @return a new ciphertext encrypts the subtraction of the plaintext in the ciphertext and the given plaintext
    */
    public static subtractPlain(publicKey: PaillierPublicKey, c: BN, m: BN): BN {
        if (publicKey == null || c == null || m == null) {
            throw new Error(CryptoException.NULL_INPUT);
        }

        let c2: BN = CryptoConsants.ONE.sub(m.mul(publicKey.getN())).umod(publicKey.getnSquare());
        return c.mul(c2).umod(publicKey.getnSquare());
    }

    /**
     * Homomorphic multiplication of a ciphertext and a constant.
     * @param publicKey the Paillier public key
     * @param c the ciphertext
     * @param k the constant
     * @return a new ciphertext encrypts the plaintext in the ciphertext multiplied by the constant
     */
    public static multiply(publicKey: PaillierPublicKey, c: BN, k: BN): BN {
        if (publicKey == null || c == null || k == null) {
            throw new Error(CryptoException.NULL_INPUT);
        }

        let nSquareRed = BN.red(publicKey.getnSquare());

        return c.toRed(nSquareRed).redPow(k);
        // return c.modPow(k, publicKey.getnSquare());
    }

}
