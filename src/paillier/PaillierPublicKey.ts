import { BigInteger } from 'big-integer';
import { CryptoException } from "../exception/CryptoException";

export default class PaillierPublicKey {
    private   n: BigInteger;
    private   nSquare: BigInteger;

    public constructor( n: BigInteger)  {
        if (n == null) {
            throw new Error(CryptoException.NULL_INPUT);
        }
        if (n.bitLength().valueOf() < 2048) {
            throw new Error(CryptoException.BIT_LENGTH_TOO_SMALL);
        }
        if (n.isNegative()) {
            throw new Error(CryptoException.PARAMETER_TOO_SMALL);
        }

        this.n = n;
        this.nSquare = n.multiply(n);
    }

    public  getN(): BigInteger {
        return this.n;
    }

    public  getnSquare(): BigInteger {
        return this.nSquare;
    }

}