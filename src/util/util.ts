import BN from 'bn.js';
import * as fs from 'fs';
const cryptoUtil = require('./bigint-crypto-utils');

import { ECPoint, KeyGenContext } from '../type';
import { CryptoConsants } from '../common/CryptoConstants';
import * as ellipticUtil from './ellipticUtil';
import { KeyGenContextVO } from 'dist/src';

export const bigIntToBN = (input: bigint) => {
  return new BN(input + '');
};

export const bnToBigInt = (input: BN) => {
  return BigInt(`0x${input.toString('hex')}`);
};

export const isProbablyPrime = (input: BN): Promise<boolean> => {
  return new Promise((resolve, reject) => {
    cryptoUtil
      .isProbablyPrime(bnToBigInt(input))
      .then((res: boolean) => resolve(res))
      .catch((err: any) => reject(err));
  });
};

export const encodeCompressECpointToHexStr = (point: ECPoint): string => {
  return point.encodeCompressed('hex');
};

export const toKeyGenContextVO = (
  keyGenCtx: KeyGenContext,
): KeyGenContextVO => {
  const X = keyGenCtx.p1.ecdsaPrivateKeyShare
    .mul(keyGenCtx.p2.ecdsaPrivateKeyShare)
    .mod(CryptoConsants.SECP256_CURVE_N);
  const keyGenCtxRes = {
    addressFromPoint: ellipticUtil.ecPointToAccountAddress(keyGenCtx.Q),
    addressFromX: ellipticUtil.privateKeyToAccountAddress(X.toString('hex')),
    x: X.toString('hex'),

    // keyGenCtx.p1.
    p1: {
      x1: keyGenCtx.p1.ecdsaPrivateKeyShare.toString('hex'),
      paillierPrivateKeyP: keyGenCtx.p1.paillierPrivateKey.p.toString('hex'),
      paillierPrivateKeyQ: keyGenCtx.p1.paillierPrivateKey.q.toString('hex'),
    },
    p2: {
      paillierPublicKeyN: keyGenCtx.p2.paillierPublicKey.N.toString('hex'),
      cKey: keyGenCtx.p2.cKey.toString('hex'),
      x2: keyGenCtx.p2.ecdsaPrivateKeyShare.toString('hex'),
    },
  };
  return keyGenCtxRes;
};

export const saveKeyGenRes = (keyGenCtx: KeyGenContext) => {
  fs.writeFileSync(
    `keyGenRes-${new Date().getTime()}.json`,
    JSON.stringify(toKeyGenContextVO(keyGenCtx)),
  );
};
