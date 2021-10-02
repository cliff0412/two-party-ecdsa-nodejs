import BN from 'bn.js'
import * as elliptic from 'elliptic';

// let curve = ec.curve;
import { ProofUtils } from './ProofUtils';
import * as util from '../util/util';
import { ECPoint } from '../type';

import { KeyGeneration } from '../protocols';
// import { PaillierKeyPair } from '../paillier';
// import { ECDlogProof } from './ECDlogProof';


let ec = new elliptic.ec('secp256k1');
let m: BN = ec.n as BN;
let g: ECPoint = ec.g as ECPoint;

test('computeChallenge', () => {


    let res1: BN = ProofUtils.computeChallenge(m, g)
    expect(res1.toString()).toBe('6984979233802560903909664569986656529885267826392860390547891078208641762644');

    let p1: ECPoint = g.mul(new BN("123456789", 10));
    let res2: BN = ProofUtils.computeChallenge(m, g, p1)
    expect(res2.toString()).toBe("88009922998874470280805636197392967853279833223700034535609448203756834200109")


    let p2: ECPoint = g.mul(new BN("12345678987654321", 10))
    let res3: BN = ProofUtils.computeChallenge(m, g, p1, p2)
    expect(res3.toString()).toBe("77241505263168613063876428786720499258762640794766964164091358550225877324326")

})

test('hashToInt', () => {


    let hash = util.encodeCompressECpointToHexStr(ec.g);
    let val = ProofUtils.hashToInt(hash, m)
    expect(val.toString()).toBe('55066263022277343669578718895168534327115444226908913489205029093179053020438');


    let input1 = "c293d9e516ea79c51c208382ae5b3ae2e3b3e2d7edeb1bfef8a94878285d1a2d";
    let val1 = ProofUtils.hashToInt(input1, m)
    expect(val1.toString()).toBe('88009922998874470280805636197392967853279833223700034535609448203756834200109');
})

test('verifyECDlogProof', () => {
    let x1 = new BN(123456789);

    let p1KeyGen: KeyGeneration = new KeyGeneration("p1");
    let Q1: ECPoint = p1KeyGen.computeEcdsaPublicKeyShare(x1);
    let ecdLogProof = ProofUtils.generateECDlogProof(Q1, x1);

    // console.log('---res---:', ProofUtils.verifyECDlogProof(ecdLogProof, g))
    expect(ProofUtils.verifyECDlogProof(ecdLogProof)).toBeTruthy();
})

// TODO: TEST FAILED
// test('verifyPaillierPublicKeyProof', async () => {

//     let p1KeyGen: KeyGeneration = new KeyGeneration("p1");

//     let keyPair: PaillierKeyPair = await p1KeyGen.generatePaillierKeyPair();
//     // let paillierPublicKey = keyPair.getPublicKey();
//     let paillierPrivateKey = keyPair.getPrivateKey();
//     let N = paillierPrivateKey.getN();

//     let paillierPublicKeyProof = ProofUtils.generatePaillierPublicKeyProof(
//         N,
//         paillierPrivateKey.getP(),
//         paillierPrivateKey.getQ()
//     );

//     // console.log('---paillierPublicKeyProof---', paillierPublicKeyProof.getN().toString())

//     let res = ProofUtils.verifyPaillierPublicKeyProof(paillierPublicKeyProof)
//     // console.log('---res---', res)
// })