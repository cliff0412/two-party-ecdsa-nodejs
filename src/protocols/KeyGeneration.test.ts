import {KeyGeneration} from './KeyGeneration';
import { ECPoint } from '../type/ECPoint';
import * as elliptic from 'elliptic';
// import BN from 'bn.js';
import * as serialization from '../util/serialization'
import * as desearilization from '../util/desearilization'
import {CryptoConsants} from '../common/CryptoConstants';
// import { ECPoint } from '../type/ECPoint';

let keyGenerationP1: KeyGeneration = new KeyGeneration(CryptoConsants.PARTY_ONE);

test('generateEcdsaPrivateKeyShare', () => {
    let res = keyGenerationP1.generateEcdsaPrivateKeyShare();
    console.log(res.toString())
})


test('computeEcdsaPublicKeyShare', () => {

    let ec = new elliptic.ec('secp256k1');
    // let curve = ec.curve;
    let g: ECPoint = ec.g;
    // console.log("--generator x ", g.getX().toString('hex'))
    // console.log("--generator y ", g.getY().toString('hex'))

   let pointInJson = serialization.ecPointToJSON(g)
   console.log(pointInJson)
   let p: ECPoint= desearilization.ecPointFromJSON(pointInJson)
    console.log(p.eq(g))
    // let encodedStr = g.encodeCompressed("hex");
    // console.log('---encoded str---: ', encodedStr)

    // var shortCurve = new elliptic.curve.short({
    //     p: 'ffffffff ffffffff ffffffff ffffffff ffffffff ffffffff fffffffe ' +
    //         'fffffc2f',
    //     a: '0',
    //     b: '7',
    //     n: new BN('ffffffff ffffffff ffffffff fffffffe baaedce6 af48a03b bfd25e8c d0364141', 16),
    //     g: curve.g,
    // });

    // let constructedGenerator:ECPoint = (curve as any).point(
    //     new BN('79be667e f9dcbbac 55a06295 ce870b07 029bfcdb 2dce28d9 59f2815b 16f81798', 16),
    //     new BN('483ada77 26a3c465 5da4fbfc 0e1108a8 fd17b448 a6855419 9c47d08f fb10d4b8', 16)
    // )
    // console.log('---isequal---',constructedGenerator.eq(g));

    // var p = shortCurve.point(
    //     new BN('79be667e f9dcbbac 55a06295 ce870b07 029bfcdb 2dce28d9 59f2815b 16f81798', 16),
    //     new BN('483ada77 26a3c465 5da4fbfc 0e1108a8 fd17b448 a6855419 9c47d08f fb10d4b8', 16)
    // );

    // console.log('--- is equal ---', g.eq(p))


    // let share = keyGenerationP1.generateEcdsaPrivateKeyShare();
    // let res = keyGenerationP1.computeEcdsaPublicKeyShare(share);

    //     let methods = [];
    //     for(let key in res) {
    //         methods.push(key)
    //     }
    //     console.log(methods);

    //    console.log((res as any).toJSON());
})