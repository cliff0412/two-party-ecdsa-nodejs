import BN from 'bn.js';
import { ECPoint,ECPointVO } from '../type/ECPoint';
import * as elliptic from 'elliptic';

import * as serialization from './serialization';

let ec = new elliptic.ec('secp256k1');
let g: ECPoint = ec.g;

test('ecPointToJSON', () => {
   let pointInJson: ECPointVO = serialization.ecPointToJSON(g)
   expect(pointInJson.x).toBe('79be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798')
   expect(pointInJson.y).toBe('483ada7726a3c4655da4fbfc0e1108a8fd17b448a68554199c47d08ffb10d4b8')


   let k1: BN = new BN(1234567890);
   let p1 = g.mul(k1);

   let point1InJson = serialization.ecPointToJSON(p1)
   expect(point1InJson.x).toBe('2b698a0f0a4041b77e63488ad48c23e8e8838dd1fb7520408b121697b782ef22')
   expect(point1InJson.y).toBe('2ee976351a7fe808101c7e79b040e5cb16afe6aa152b87e398d160c306a31bac')

   let k2: BN = new BN("12345678987654321", 10);
   let p2 = g.mul(k2);

   let point2InJson = serialization.ecPointToJSON(p2)
   expect(point2InJson.x).toBe('92964cea710e6482894462cff8a455c439f476d26639c01d1d88e9ab4c1583ab')
   expect(point2InJson.y).toBe('d33f2f3fcba320abdb87613698f4bb2c2facdbe6c3b6093509ffa42edbc729a9')


})

test('bnToHexString', () => {
   let bn = new BN('483ada7726a3c4655da4fbfc0e1108a8fd17b448a68554199c47d08ffb10d4b8', 'hex')
   expect(serialization.bnToHexString(bn)).toEqual('483ada7726a3c4655da4fbfc0e1108a8fd17b448a68554199c47d08ffb10d4b8')
})