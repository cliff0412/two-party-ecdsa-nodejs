import BN from 'bn.js';
import elliptic from 'elliptic';
const { keccak256, keccak256s } = require('eth-lib/lib/hash');

const minUtils = require('minimalistic-crypto-utils');
import { Signature, ECPoint } from '../type';

const EC = elliptic.ec;
const ec = new EC('secp256k1');

export const verifySig = (msg: BN, r: BN, s: BN, pubKey: Buffer) => {
  const sig = toDER({ r, s });
  // console.log("sig", sig)
  return ec.verify(msg, sig, pubKey);
};

export const ecPointToAccountAddress = (point: ECPoint): string => {
  const publicKey = '0x' + point.encode('hex', false).slice(2);
  const publicHash = keccak256(publicKey);
  const address = toChecksum('0x' + publicHash.slice(-40));
  return address;
};

/**
 * privateKeyToAccount
 * @param privateKey no leading '0x'
 */
export const privateKeyToAccountAddress = (privateKey: string) => {
  let priv = new BN(privateKey, 'hex');
  priv = priv.umod(ec.curve.n);

  const pub = ec.g.mul(priv);
  return ecPointToAccountAddress(pub);
};

/**
 * calcunate final v value from signature recovery
 * @param recovery a value between 0-4
 * @param chainId kovan: 42, mainnet: 1
 */
export const formSigVval = (recovery: number, chainId: number) => {
  let v = recovery + 27;

  // only if _implementsEIP155 and network is kovan
  if (chainId !== 1) v += chainId * 2 + 8;
  return v;
};

const toChecksum = (address: string) => {
  const addressHash = keccak256s(address.slice(2));
  let checksumAddress = '0x';
  for (let i = 0; i < 40; i++)
    checksumAddress +=
      parseInt(addressHash[i + 2], 16) > 7
        ? address[i + 2].toUpperCase()
        : address[i + 2];
  return checksumAddress;
};

const toDER = (sig: Signature) => {
  let r = sig.r.toArray();
  let s = sig.s.toArray();

  // Pad values
  if (r[0] & 0x80) r = [0].concat(r);
  // Pad values
  if (s[0] & 0x80) s = [0].concat(s);

  r = rmPadding(r);
  s = rmPadding(s);

  while (!s[0] && !(s[1] & 0x80)) {
    s = s.slice(1);
  }
  let arr = [0x02];
  constructLength(arr, r.length);
  arr = arr.concat(r);
  arr.push(0x02);
  constructLength(arr, s.length);
  const backHalf = arr.concat(s);
  let res = [0x30];
  constructLength(res, backHalf.length);
  res = res.concat(backHalf);
  return minUtils.encode(res);
};

function rmPadding(buf: any[]) {
  let i = 0;
  const len = buf.length - 1;
  while (!buf[i] && !(buf[i + 1] & 0x80) && i < len) {
    i++;
  }
  if (i === 0) {
    return buf;
  }
  return buf.slice(i);
}

function constructLength(arr: any[], len: number) {
  if (len < 0x80) {
    arr.push(len);
    return;
  }
  let octets = 1 + ((Math.log(len) / Math.LN2) >>> 3);
  arr.push(octets | 0x80);
  while (--octets) {
    arr.push((len >>> (octets << 3)) & 0xff);
  }
  arr.push(len);
}
