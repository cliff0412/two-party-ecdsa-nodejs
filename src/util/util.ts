

import BN from 'bn.js';

export const bigIntToBN = (input: bigint) => {
    return new BN(input + "");
}

export const bnToBigInt = (input: BN) => {
    return BigInt(`0x${input.toString('hex')}`);
}