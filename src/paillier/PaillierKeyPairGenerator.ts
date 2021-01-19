import BN from "bn.js";
import * as bigintCryptoUtils from 'bigint-crypto-utils'

import PaillierKeyPair from './PaillierKeyPair';
import PaillierPublicKey from './PaillierPublicKey';
import PaillierPrivateKey from './PaillierPrivateKey';

import { CryptoConsants } from '../common/CryptoConstants';
import * as util from '../util/util';


export class PaillierKeyPairGenerator {

    private bitLength: number;

    public constructor(bitLength: number) {
        this.bitLength = bitLength;
    }


    public async generateKeyPair(): Promise<PaillierKeyPair> {
        // random = new SecureRandom();

        let p: BN, q: BN;
        let primeBitlength: number = (this.bitLength + 1) / 2;

        let squaredLowBound: BN = CryptoConsants.ONE.shln(this.bitLength - 1);
        let squaredUpBound: BN = CryptoConsants.ONE.shln(this.bitLength);

        if ((this.bitLength & 1) == 0) {     // bitLength is odd number

            p = util.bigIntToBN(await bigintCryptoUtils.prime(primeBitlength));

            while (p.mul(p).lt(squaredLowBound)) {
                p = util.bigIntToBN(await bigintCryptoUtils.prime(primeBitlength));
            }
            q = util.bigIntToBN(await bigintCryptoUtils.prime(primeBitlength));
            while (q.mul(q).lt(squaredLowBound) || q.eq(p)) {
                q = util.bigIntToBN(await bigintCryptoUtils.prime(primeBitlength));
            }
        } else {                        // bigLength is even number
            p = util.bigIntToBN(await bigintCryptoUtils.prime(primeBitlength));
            while (p.mul(p).gte(squaredUpBound)) {
                p = util.bigIntToBN(await bigintCryptoUtils.prime(primeBitlength));
            }
            q = util.bigIntToBN(await bigintCryptoUtils.prime(primeBitlength));
            while (q.mul(q).gte(squaredUpBound) || q.eq(p)) {
                q = util.bigIntToBN(await bigintCryptoUtils.prime(primeBitlength));
            }
        }

        let n: BN = p.mul(q);

        let publicKey: PaillierPublicKey = new PaillierPublicKey(n);
        let privateKey: PaillierPrivateKey = new PaillierPrivateKey(p, q);

        return new PaillierKeyPair(publicKey, privateKey);
    }
}

export default PaillierKeyPairGenerator;