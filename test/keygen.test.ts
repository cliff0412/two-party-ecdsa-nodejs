import BN from 'bn.js';
import * as elliptic from 'elliptic';

// import * as serialization from './serialization';


import {
    KeyGeneration,
    KeyGenContextP1,
    KeyGenContextP2,
    ECPoint
} from '../src'


let ec = new elliptic.ec('secp256k1');
let g: ECPoint = ec.g;

beforeAll(() => {
    console.log('---before all tests.-----')
});


test('keygen', () => {
    let p1KeyGen: KeyGeneration = new KeyGeneration("p1");

    let keyGenContextP1: KeyGenContextP1 = new KeyGenContextP1();

    let p2KeyGen: KeyGeneration = new KeyGeneration("p2");
    let keyGenContextP2: KeyGenContextP2 = new KeyGenContextP2();


    // P1 choosing a random x1 and
    // computing Q1 = x1 ·G, and then committing to Q1 along with a zero-knowledge
    // proof of knowledge of x1, the discrete log of Q1
    let x1 = p1KeyGen.generateEcdsaPrivateKeyShare();
    let Q1: ECPoint = p1KeyGen.computeEcdsaPublicKeyShare(x1);

    let upperBound = ec.n.div(new BN(3));
    expect(!x1.isNeg() && x1.lte(upperBound)).toBeTruthy()

    // ECDlogProof Q1ECDlogProof = ProofUtils.generateECDlogProof(G, Q1, x1);
})