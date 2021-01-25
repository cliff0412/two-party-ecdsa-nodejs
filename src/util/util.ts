import BN from 'bn.js';
import * as fs from 'fs';
const cryptoUtil = require("./bigint-crypto-utils");

import { ECPoint, KeyGenContext } from '../type';
import { CryptoConsants } from '../common/CryptoConstants'
import * as ellipticUtil from './ellipticUtil';

export const bigIntToBN = (input: bigint) => {
    return new BN(input + "");
}

export const bnToBigInt = (input: BN) => {
    return BigInt(`0x${input.toString('hex')}`);
}

export const isProbablyPrime = (input: BN): Promise<boolean> => {

    return new Promise((resolve, reject) => {
        cryptoUtil.isProbablyPrime(bnToBigInt(input))
            .then((res: boolean) => resolve(res))
            .catch((err: any) => reject(err))
    });

}

export const encodeCompressECpointToHexStr = (point: ECPoint): string => {
    return point.encodeCompressed('hex');
}

export const saveKeyGenRes = (keyGen: KeyGenContext) => {
    let X = keyGen.p1.ecdsaPrivateKeyShare
        .mul(keyGen.p2.ecdsaPrivateKeyShare)
        .mod(CryptoConsants.SECP256_CURVE_N)
    let keyGenRes = {
        addressFromPoint: ellipticUtil.ecPointToAccountAddress(keyGen.Q),
        addressFromX: ellipticUtil.privateKeyToAccountAddress(X.toString("hex")),
        x: X.toString("hex"),

        // keyGen.p1.
        p1: {
            x1: keyGen.p1.ecdsaPrivateKeyShare.toString('hex'),
            paillierPrivateKeyP: keyGen.p1.paillierPrivateKey.p.toString("hex"),
            paillierPrivateKeyQ: keyGen.p1.paillierPrivateKey.q.toString("hex"),
        },
        p2: {
            paillierPublicKeyN: keyGen.p2.paillierPublicKey.N.toString("hex"),
            cKey: keyGen.p2.cKey.toString("hex"),
            x2: keyGen.p2.ecdsaPrivateKeyShare.toString('hex')
        }

    }
    fs.writeFileSync(`keyGenRes-${new Date().getTime()}.json`, JSON.stringify(keyGenRes))
}