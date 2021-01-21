
import { ECPoint } from '../type/ECPoint';

export const ecPointToJSON = (point: ECPoint): string[] => {
    let x: string = point.getX().toString('hex')
    let y: string = point.getY().toString('hex')
    return [x, y]
}