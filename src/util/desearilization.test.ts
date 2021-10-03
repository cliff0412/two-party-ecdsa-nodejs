import { ECPoint } from '../type/ECPoint';
import * as elliptic from 'elliptic';
import BN from 'bn.js';
import * as desearilization from './desearilization';


let ec = new elliptic.ec('secp256k1');
let g: ECPoint = ec.g;

test('ecPointFromJSON', () => {

    let pointInJson = {
        x: '79be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798',
        y: '483ada7726a3c4655da4fbfc0e1108a8fd17b448a68554199c47d08ffb10d4b8'
    }

    let constructedG: ECPoint = desearilization.ecPointFromJSON(pointInJson);
    expect(g.eq(constructedG)).toBeTruthy()


    let point1InJson = {
        x: '2b698a0f0a4041b77e63488ad48c23e8e8838dd1fb7520408b121697b782ef22',
        y: '2ee976351a7fe808101c7e79b040e5cb16afe6aa152b87e398d160c306a31bac'
    }

    let constructedP1: ECPoint = desearilization.ecPointFromJSON(point1InJson);
    let expectedPoint1: ECPoint = g.mul(new BN(1234567890))
    expect(constructedP1.eq(expectedPoint1)).toBeTruthy()

    let point2InJson = {
        x: '92964cea710e6482894462cff8a455c439f476d26639c01d1d88e9ab4c1583ab',
        y: 'd33f2f3fcba320abdb87613698f4bb2c2facdbe6c3b6093509ffa42edbc729a9'
    }

    let constructedP2: ECPoint = desearilization.ecPointFromJSON(point2InJson);
    let expectedPoint2: ECPoint = g.mul(new BN("12345678987654321", 10))
    expect(constructedP2.eq(expectedPoint2)).toBeTruthy()
})

test('bnFromHexString', () => {
    let bn = new BN('483ada7726a3c4655da4fbfc0e1108a8fd17b448a68554199c47d08ffb10d4b8', 'hex')
    expect(desearilization.bnFromHexString('483ada7726a3c4655da4fbfc0e1108a8fd17b448a68554199c47d08ffb10d4b8').eq(bn)).toBeTruthy()
 })