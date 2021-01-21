import BN from 'bn.js';
import * as elliptic from 'elliptic';

import { ECPoint } from '../type/ECPoint';

let ec = new elliptic.ec('secp256k1');
let curve = ec.curve;

export const ecPointFromJSON = (coordsInHexString: string[]): ECPoint => {
    let x: BN = new BN(coordsInHexString[0], 16)
    let y: BN = new BN(coordsInHexString[1], 16)

    return (curve as any).point(x, y)
}