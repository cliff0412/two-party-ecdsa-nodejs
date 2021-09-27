import BN from 'bn.js';
import * as elliptic from 'elliptic';

import { ECPoint } from '../type/ECPoint';

const ec = new elliptic.ec('secp256k1');
const curve = ec.curve;

export const ecPointFromJSON = (coordsInHexString: string[]): ECPoint => {
  const x: BN = new BN(coordsInHexString[0], 16);
  const y: BN = new BN(coordsInHexString[1], 16);

  return (curve as any).point(x, y);
};
