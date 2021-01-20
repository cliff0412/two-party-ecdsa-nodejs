import BN from 'bn.js';

const cryptoUtil = require("./bigint-crypto-utils");

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

