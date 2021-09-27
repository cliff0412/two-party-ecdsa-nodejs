import { ECPoint } from '../type/ECPoint';

export const ecPointToJSON = (point: ECPoint): string[] => {
  const x: string = point.getX().toString('hex');
  const y: string = point.getY().toString('hex');
  return [x, y];
};
