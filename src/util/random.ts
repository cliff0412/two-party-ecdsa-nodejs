import BN from 'bn.js';

import * as util from './util';
const cryptoUtil = require('./bigint-crypto-utils');

export const randomPrime = async (bitLength: number): Promise<BN> => {
  // console.log('using bigLength in randomPrime: ', bitLength);
  return new Promise((resolve, reject) => {
    // console.log("cryptoUtil: ", cryptoUtil)
    cryptoUtil
      .prime(bitLength)
      .then((primeNum: bigint) => {
        // console.log("generated random prime: ", primeNum.toString())
        resolve(new BN(primeNum.toString(), 10));
      })
      .catch((err: any) => {
        // console.log('error in randomPrime ', err);
        reject(err);
      });
  });
};

export const randBetween = (min: BN, max: BN) => {
  return util.bigIntToBN(
    cryptoUtil.randBetween(util.bnToBigInt(max), util.bnToBigInt(min)),
  );
};
