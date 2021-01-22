import BN from 'bn.js';
import * as elliptic from 'elliptic';

import {
    KeyGeneration,
    KeyGenContextP1,
    KeyGenContextP2,
    ProofUtils,
    ECPoint,
    ECDlogProof,
    HashCommitter,
    SigningContextP1,
    SigningContextP2,
    Paillier,
    PaillierPublicKey,
    util,
    random
} from '../src'

import {
    CryptoException
} from '../src/exception/CryptoException';


import {
    CryptoConsants
} from '../src/common/CryptoConstants';

let ec = new elliptic.ec('secp256k1');
// let g: ECPoint = ec.g;

let signingContextP1: SigningContextP1;
let signingContextP2: SigningContextP2;

beforeAll(() => {
    console.log('---before all tests.-----')
});


test('keygen', async () => {
    let p1KeyGen: KeyGeneration = new KeyGeneration("p1");

    let keyGenContextP1: KeyGenContextP1 = new KeyGenContextP1();

    let p2KeyGen: KeyGeneration = new KeyGeneration("p2");
    let keyGenContextP2: KeyGenContextP2 = new KeyGenContextP2();


    // P1 choosing a random x1 and
    // computing Q1 = x1 ·G, and then committing to Q1 along with a zero-knowledge
    // proof of knowledge of x1, the discrete log of Q1
    let x1 = p1KeyGen.generateEcdsaPrivateKeyShare();
    let Q1: ECPoint = p1KeyGen.computeEcdsaPublicKeyShare(x1);

    let upperBound: BN = (ec.n as BN).div(new BN(3));
    expect(!x1.isNeg() && x1.lte(upperBound)).toBeTruthy()

    let Q1ECDlogProof: ECDlogProof = ProofUtils.generateECDlogProof(Q1, x1);

    // P1 process first message, sends p1Commitment
    let p1Commitment = HashCommitter.commit(
        HashCommitter.getRandomBytes(),
        util.encodeCompressECpointToHexStr(Q1),
        util.encodeCompressECpointToHexStr(Q1ECDlogProof.getQ()),
        util.encodeCompressECpointToHexStr(Q1ECDlogProof.getX()),
        Q1ECDlogProof.getZ().toString('hex')
    );

    keyGenContextP1.setEcdsaPrivateKeyShare(x1);
    keyGenContextP1.setEcdsaPublicKeyShare(Q1);
    keyGenContextP1.setQ1ECDlogProof(Q1ECDlogProof);

    // P2 process first message, receives p1Commitment, sends Q2, Q2ECDlogProof;
    keyGenContextP2.setCommitment(p1Commitment);

    // P2 choosing a random x2 and
    // computing Q2 = x2 ·G, and then committing to Q2 along with a zero-knowledge
    // proof of knowledge of x2, the discrete log of Q2
    let x2 = p2KeyGen.generateEcdsaPrivateKeyShare();
    expect(!x2.isNeg() && x2.lt(ec.n as BN)).toBeTruthy()

    let Q2 = p2KeyGen.computeEcdsaPublicKeyShare(x2);
    let Q2ECDlogProof = ProofUtils.generateECDlogProof(Q2, x2);

    keyGenContextP2.setEcdsaPrivateKeyShare(x2);

    // P1 process second message, receives Q2, Q2ECDlogProof
    // sends Q1, Q1ECDlogProof, N, cKey, paillierPublicKeyProof, paillierAndDlogProof
    if (!ProofUtils.verifyECDlogProof(Q2ECDlogProof)) {
        throw new Error(CryptoException.VERIFY_PROOF_FAILED);
    }

    let keyPair = await p1KeyGen.generatePaillierKeyPair();
    let paillierPublicKey = keyPair.getPublicKey();
    let paillierPrivateKey = keyPair.getPrivateKey();
    let N = paillierPrivateKey.getN();


    let rKey = random.randBetween(CryptoConsants.ONE, N.sub(CryptoConsants.ONE))
    let cKey = Paillier.encryptWithRandom(paillierPublicKey, keyGenContextP1.getEcdsaPrivateKeyShare(), rKey);

    // let paillierPublicKeyProof = ProofUtils.generatePaillierPublicKeyProof(
    //     N,
    //     paillierPrivateKey.getP(),
    //     paillierPrivateKey.getQ()
    // );

    // PaillierAndDlogProof paillierAndDlogProof = ProofUtils.generatePaillierAndDlogProof(
    //     G,
    //     keyGenContextP1.getEcdsaPublicKeyShare(),
    //     keyGenContextP1.getEcdsaPrivateKeyShare(),
    //     N,
    //     cKey,
    //     rKey
    // );

    let p1Q = p1KeyGen.computeEcdsaPublicKey(keyGenContextP1.getEcdsaPrivateKeyShare(), Q2ECDlogProof.getQ());
    signingContextP1 = new SigningContextP1(paillierPrivateKey, keyGenContextP1.getEcdsaPrivateKeyShare(), p1Q);

    // P2 processes second message, receives (Q1, Q1ECDlogProof, N, cKey, paillierPublicKeyProof, paillierAndDlogProof).
    if (!HashCommitter.verify(keyGenContextP2.getCommitment(),
        util.encodeCompressECpointToHexStr(Q1ECDlogProof.getQ()),
        util.encodeCompressECpointToHexStr(Q1ECDlogProof.getQ()),
        util.encodeCompressECpointToHexStr(Q1ECDlogProof.getX()),
        Q1ECDlogProof.getZ().toString("hex"))) {
        throw new Error(CryptoException.VERIFY_COMMITMENT_FAILED);
    }
    if (!ProofUtils.verifyECDlogProof(Q1ECDlogProof)
        // || !ProofUtils.verifyPaillierPublicKeyProof(paillierPublicKeyProof)
        // || !ProofUtils.verifyPaillierAndDlogProof(paillierAndDlogProof, G, Q1ECDlogProof.getQ(), N, cKey)
    ) {
        throw new Error(CryptoException.VERIFY_PROOF_FAILED);
    }


    if (N.bitLength() < ((ec.n as BN).bitLength() * 4 + 2)) {
        throw new Error(CryptoException.INVALID_PAILLIER_PUBLIC_KEY);
    }


    let p2Q = p2KeyGen.computeEcdsaPublicKey(keyGenContextP2.getEcdsaPrivateKeyShare(), Q1ECDlogProof.getQ());
    signingContextP2 = new SigningContextP2(new PaillierPublicKey(N), cKey, keyGenContextP2.getEcdsaPrivateKeyShare(), p2Q);

    console.log(signingContextP1.getEcdsaPrivateKeyShare().toString("hex"))
    console.log(signingContextP2.getEcdsaPrivateKeyShare().toString("hex"))

    // console.log('---p1Q--- x: ', p1Q.getX().toString("hex"))
    // console.log('---p2Q--- x: ', p2Q.getX().toString("hex"))
    expect(p1Q.getX().toString("hex")).toEqual(p2Q.getX().toString("hex"))

    // console.log('---p1Q--- y: ', p1Q.getY().toString("hex"))
    // console.log('---p2Q--- y: ', p2Q.getY().toString("hex"))
    expect(p1Q.getY().toString("hex")).toEqual(p2Q.getY().toString("hex"))

})