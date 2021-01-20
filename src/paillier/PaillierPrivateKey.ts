import bigInt, { BigInteger } from 'big-integer';

import { CryptoException } from "../exception/CryptoException";

export default class PaillierPrivateKey {

    private p: BigInteger;
    private q: BigInteger;
    private n: BigInteger;
    private pSquare: BigInteger;
    private qSquare: BigInteger;
    private nSquare: BigInteger;
    private lambda: BigInteger;
    private lambdaInv: BigInteger;
    private pSquareInv: BigInteger;
    private qSquareInv: BigInteger;

    public constructor(p: BigInteger, q: BigInteger) {

        if (p == null || q == null) {
            throw new Error(CryptoException.NULL_INPUT);
        }
        if (p.bitLength().valueOf() < 1024 || q.bitLength().valueOf() < 1024) {
            throw new Error(CryptoException.BIT_LENGTH_TOO_SMALL);
        }



        if (
            !p.isPrime() ||
            !q.isPrime()
        ) {
            throw new Error(CryptoException.PARAMETER_IS_NOT_PRIME);
        }
        if (p.eq(q)) {
            throw new Error(CryptoException.SAME_PRIMES);
        }

        const ONE =  bigInt(1);

        this.p = p;
        this.q = q;
        this.n = p.multiply(q);
        this.nSquare = this.n.multiply(this.n);
        let pMinusOne: BigInteger = p.subtract(ONE);
        let qMinusOne: BigInteger = q.subtract(ONE);
        let d: BigInteger = bigInt.gcd(pMinusOne,qMinusOne );
        this.lambda = pMinusOne.multiply(qMinusOne).divide(d);  // lambda = lcm( p-1, q-1 )



        this.lambdaInv = this.lambda.modInv(this.n);

        this.pSquare = p.multiply(p);
        this.qSquare = q.multiply(q);


        // let pSquareInRed = this.pSquare.toRed(BN.red(this.qSquare));
        this.pSquareInv = this.pSquare.modInv(this.qSquare);

        // let qSquareInRed = this.qSquare.toRed(BN.red(this.pSquare));
        this.qSquareInv = this.qSquare.modInv(this.pSquare);

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