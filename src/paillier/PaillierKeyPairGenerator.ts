
import { BigInteger } from 'big-integer';

import PaillierKeyPair from './PaillierKeyPair';
import PaillierPublicKey from './PaillierPublicKey';
import PaillierPrivateKey from './PaillierPrivateKey';

import { CryptoConsants } from '../common/CryptoConstants';
import * as random from '../util/random';


export class PaillierKeyPairGenerator {

    private bitLength: number;

    public constructor(bitLength: number) {
        this.bitLength = bitLength;
    }

    // public generateKeyPair1() {
    //     const {publicKey, privateKey} = paillier.generateRandomKeys(2048);
    // }


    public async generateKeyPair(): Promise<PaillierKeyPair> {
        let startTime = new Date().getTime();

        let p: BigInteger, q: BigInteger;
        let primeBitlength: number = Math.floor((this.bitLength + 1) / 2);

        let squaredLowBound: BigInteger = CryptoConsants.BN_ONE.shiftLeft(this.bitLength - 1);
        let squaredUpBound: BigInteger = CryptoConsants.BN_ONE.shiftLeft(this.bitLength);

        if ((this.bitLength & 1) == 0) {     // bitLength is odd number

            p = await random.randomPrime(primeBitlength);

            while (p.multiply(p).lt(squaredLowBound)) {
                p = await random.randomPrime(primeBitlength);
            }
            q = await random.randomPrime(primeBitlength);
            while (q.multiply(q).lt(squaredLowBound) || q.eq(p)) {
                q = await random.randomPrime(primeBitlength);
            }
        } else {                        // bigLength is even number
            p = await random.randomPrime(primeBitlength);
            while (p.multiply(p).greaterOrEquals(squaredUpBound)) {
                p = await random.randomPrime(primeBitlength);
            }
            q = await random.randomPrime(primeBitlength);
            while (q.multiply(q).greaterOrEquals(squaredUpBound) || q.eq(p)) {
                q = await random.randomPrime(primeBitlength);
            }
        }

        let n: BigInteger = p.multiply(q);

        let publicKey: PaillierPublicKey = new PaillierPublicKey(n);
        let privateKey: PaillierPrivateKey = new PaillierPrivateKey(p, q);
        let endTime = new Date().getTime();
        console.log(`total time in generating keypair ${(endTime - startTime)/1000} seconds`)
        return new PaillierKeyPair(publicKey, privateKey);
    }
}

export default PaillierKeyPairGenerator;