import BN from 'bn.js';
import * as elliptic from 'elliptic';

import { ECPoint } from '../type/ECPoint';
import * as random from "../util/random";
import { CryptoConsants } from '../common/CryptoConstants'
import { CryptoException } from "../exception/CryptoException";


export default class KeyGenerationP1 {

    private ec: elliptic.ec;

    public constructor() {
        this.ec = new elliptic.ec('secp256k1');
    }
    public generateEcdsaPrivateKeyShare(): BN {

        let N: BN = (this.ec as elliptic.ec).n as BN;
        return random.randBetween(CryptoConsants.ONE, N.div(new BN(3)));
    }

    public computeEcdsaPublicKeyShare(ecdsaPrivateKeyShare: BN): ECPoint {
        if (ecdsaPrivateKeyShare == null) {
            throw new Error(CryptoException.NULL_INPUT);
        }

        let subN: BN = ((this.ec as elliptic.ec).n as BN).div(new BN(3))
        if (ecdsaPrivateKeyShare.lt(CryptoConsants.ONE) ||
            ecdsaPrivateKeyShare.gt(subN)) {
            throw new Error(CryptoException.PARAMETER_OUT_OF_RANGE);
        }
        return (this.ec as elliptic.ec).g.mul(ecdsaPrivateKeyShare)
    }
}