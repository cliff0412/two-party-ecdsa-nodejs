import BN from 'bn.js'
import { ECPoint, ECPointVO } from '../type/ECPoint';

export const ecPointToJSON = (point: ECPoint): ECPointVO => {
  const x: string = point.getX().toString('hex');
  const y: string = point.getY().toString('hex');
  return {
    x,
    y
  }
};

export const bnToHexString = (bn: BN): string => {
  return bn.toBuffer().toString("hex")
}
