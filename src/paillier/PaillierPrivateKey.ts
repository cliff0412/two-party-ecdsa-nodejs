import BN from "bn.js";

import { CryptoException } from "../exception/CryptoException";
import * as util from '../util/util';

export default class PaillierPrivateKey {

    private p: BN;
    private q: BN;
    private n: BN;
    private pSquare: BN;
    private qSquare: BN;
    private nSquare: BN;
    private lambda: BN;
    private lambdaInv: BN;
    private pSquareInv: BN;
    private qSquareInv: BN;

    public constructor(p: BN, q: BN) {

        if (p == null || q == null) {
            throw new Error(CryptoException.NULL_INPUT);
        }
        if (p.bitLength() < 1024 || q.bitLength() < 1024) {
            throw new Error(CryptoException.BIT_LENGTH_TOO_SMALL);
        }

        if (

            !util.isProbablyPrime(p) ||
            !util.isProbablyPrime(q)
        ) {
            throw new Error(CryptoException.PARAMETER_IS_NOT_PRIME);
        }
        if (p.eq(q)) {
            throw new Error(CryptoException.SAME_PRIMES);
        }

        const ONE = new BN(1);

        this.p = p;
        this.q = q;
        this.n = p.mul(q);
        this.nSquare = this.n.mul(this.n);
        let pMinusOne: BN = p.sub(ONE);
        let qMinusOne: BN = q.sub(ONE);
        let d: BN = pMinusOne.gcd(qMinusOne);
        this.lambda = pMinusOne.mul(qMinusOne).div(d);  // lambda = lcm( p-1, q-1 )


        let red = BN.red(this.n);
        let lambdaInRed = this.lambda.toRed(red);

        this.lambdaInv = lambdaInRed.redInvm();

        this.pSquare = p.mul(p);
        this.qSquare = q.mul(q);


        let pSquareInRed = this.pSquare.toRed(BN.red(this.qSquare));
        this.pSquareInv = pSquareInRed.redInvm();

        let qSquareInRed = this.qSquare.toRed(BN.red(this.pSquare));
        this.qSquareInv = qSquareInRed.redInvm();

    }

    public getP() {
        return this.p;
    }

    public getQ() {
        return this.q;
    }

    public getN() {
        return this.n;
    }

    public getpSquare() {
        return this.pSquare;
    }

    public getqSquare() {
        return this.qSquare;
    }

    public getnSquare() {
        return this.nSquare;
    }

    public getLambda() {
        return this.lambda;
    }

    public getLambdaInv() {
        return this.lambdaInv;
    }

    public getpSquareInv() {
        return this.pSquareInv;
    }

    public getqSquareInv() {
        return this.qSquareInv;
    }

}