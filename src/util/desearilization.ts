import BN from 'bn.js';
import * as elliptic from 'elliptic';

import { ECPoint, ECPointVO } from '../type/ECPoint';

const ec = new elliptic.ec('secp256k1');
const curve = ec.curve;

export const ecPointFromJSON = (coordsInHexString: ECPointVO): ECPoint => {
  const x: BN = new BN(coordsInHexString.x, 16);
  const y: BN = new BN(coordsInHexString.y, 16);

  return (curve as any).point(x, y);
};

export const bnFromHexString = (input: string): BN => {
  return new BN(input, 'hex')
}