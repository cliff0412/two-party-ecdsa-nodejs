import BN from 'bn.js'
import * as elliptic from 'elliptic';
import sinon from 'sinon';
import { ProofUtils } from './ProofUtils';
import * as randomUtil from '../util/random';
import { ECPoint } from '../type';
import { bnToHexString } from '../util/serialization';
import {encodeCompressECpointToHexStr} from '../util/util';
import { KeyGeneration } from '../protocols';
import { ECDlogProof, ECDlogProofVO } from '.';
// import { PaillierKeyPair } from '../paillier';
// import { ECDlogProof } from './ECDlogProof';

describe("proofUtils", () => {
    let ec = new elliptic.ec('secp256k1');
    let m: BN = ec.n as BN;
    let g: ECPoint = ec.g as ECPoint;

    it('computeChallenge', () => {

        expect(bnToHexString(ProofUtils.computeChallenge(m, g))).toBe('0f715baf5d4c2ed329785cef29e562f73488c8a2bb9dbc5700b361d54b9b0554');

        const p1: ECPoint = g.mul(new BN("123456789", 10));
        expect(bnToHexString(ProofUtils.computeChallenge(m, g, p1))).toBe("c293d9e516ea79c51c208382ae5b3ae2e3b3e2d7edeb1bfef8a94878285d1a2d")

        const p2: ECPoint = g.mul(new BN("12345678987654321", 10))
        expect(bnToHexString(ProofUtils.computeChallenge(m, g, p1, p2))).toBe("aac524881ae12e9f7085ad37ac2faffe39601fb13d939e99907b0d61f299d226")
    })

    it('hashToInt', () => {
        const hash = encodeCompressECpointToHexStr(ec.g);
        expect(bnToHexString(ProofUtils.hashToInt(hash, m))).toEqual('79be667ef9dcbbac55a06295ce870b098d3e430dcf3ce861da4dc441768b9516');

        const input1 = "c293d9e516ea79c51c208382ae5b3ae2e3b3e2d7edeb1bfef8a94878285d1a2d";
        expect(bnToHexString(ProofUtils.hashToInt(input1, m))).toEqual('c293d9e516ea79c51c208382ae5b3ae2e3b3e2d7edeb1bfef8a94878285d1a2d');
    })

    it('verifyECDlogProof', () => {
        const stub = sinon.stub(randomUtil, "randBetween");
        stub.callsFake(() => new BN("29f335c69a98f19c816fadb7dab058f1e168c027f5be11e24512a253108bb29c", "hex"))
        
        const x1 = new BN("1acd", "hex");
        const p1KeyGen: KeyGeneration = new KeyGeneration("p1");
        const Q1: ECPoint = p1KeyGen.computeEcdsaPublicKeyShare(x1);
        const ecdLogProof = ProofUtils.generateECDlogProof(Q1, x1);
        const proofVO = ecdLogProof.toJson();

        expect(proofVO.q.x).toEqual('a47e1331b5fdbedce490497cbff1088dba72070d3cfc7997fa388fc32f80b451');
        expect(proofVO.q.y).toEqual('ca54b8befff004654086c75bda3ccb9c06244746522124ecec22666ea9576b19');
        expect(proofVO.x.x).toEqual('848abb1a513058a1706b989c21547683cbf8895c7bca0fea5daac1748cf5999b');
        expect(proofVO.x.y).toEqual('f25a961bcedf3b8a3b7cc0f873b50592fb87e19be083ce0cc0492753f6276df8');
        expect(proofVO.z).toEqual('9a48e8873dc7f09961d7df192cf911f83fa1e9da771ca91a202f884386c27598');
        stub.restore();
 
    })

    it('verifyECDlogProof', () => {
        const x1 = new BN(123456789);

        const p1KeyGen: KeyGeneration = new KeyGeneration("p1");
        const Q1: ECPoint = p1KeyGen.computeEcdsaPublicKeyShare(x1);
        const ecdLogProof = ProofUtils.generateECDlogProof(Q1, x1);
        expect(ProofUtils.verifyECDlogProof(ecdLogProof)).toBeTruthy();


        // produced by java service
        const ecdLogProofVo: ECDlogProofVO = {
            q: { "x": "a47e1331b5fdbedce490497cbff1088dba72070d3cfc7997fa388fc32f80b451", "y": "ca54b8befff004654086c75bda3ccb9c06244746522124ecec22666ea9576b19" },
            x: { "x": "848abb1a513058a1706b989c21547683cbf8895c7bca0fea5daac1748cf5999b", "y": "f25a961bcedf3b8a3b7cc0f873b50592fb87e19be083ce0cc0492753f6276df8" },
            z: "009a48e8873dc7f09961d7df192cf911f83fa1e9da771ca91a202f884386c27598"
        }
        const proof = ECDlogProof.fromJson(ecdLogProofVo)
        expect(ProofUtils.verifyECDlogProof(proof)).toBeTruthy();
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

})

