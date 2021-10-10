import BN from 'bn.js'
import * as elliptic from 'elliptic';
import sinon from 'sinon';
import { ProofUtils } from './ProofUtils';
import * as randomUtil from '../util/random';
import { ECPoint } from '../type';
import { bnToHexString } from '../util/serialization';
import { encodeCompressECpointToHexStr } from '../util/util';
import { KeyGeneration } from '../protocols';
import { ECDlogProof, ECDlogProofVO } from '.';
import { PaillierKeyPair } from '../paillier';
import { bnFromHexString } from '../util/desearilization';

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

    it('generateBigInteger', async () => {
        const m = new BN(13);
        const inBN = new BN(7);
        const result = ProofUtils.generateBigInteger(m, inBN);
        expect(bnToHexString(result)).toEqual("07")

        const N = bnFromHexString("cfb3eacd3a68ad2a904c236473bac84ef0e7ef276df1f4230c8249a15ffc2f71a8af847c8fbaceaef088b7e9829e81a90c0c357b7f8dcd68a43fbcaff2435a661e87527eaf255960437fe31ac88c97427b94c9e0431fbc3597fcd0c260687cb6ada56f932633b9b6b3951cd92d9be586f8a3926af4fc9e59fdb40a74b08c9d1509c82c3efdeabbe1887c8c691bb8b7846c7da26e5f04b3c93c1cb79330bf867a37b0360888a607231b2a3d858fd7041f2e93bdc03c1e675c930b886d4aab97123247295f0d4fcc91d14e95594d096588d3cee1365450846f5e46c2eec02978de962882303996ba8557284b37ad5d8123c25e36c35c08b500b7d6d0fcf93ec06f");

        const temp1 = bnFromHexString("cfb3eacd3a68ad2a904c236473bac84ef0e7ef276df1f4230c8249a15ffc2f71a8af847c8fbaceaef088b7e9829e81a90c0c357b7f8dcd68a43fbcaff2435a661e87527eaf255960437fe31ac88c97427b94c9e0431fbc3597fcd0c260687cb6ada56f932633b9b6b3951cd92d9be586f8a3926af4fc9e59fdb40a74b08c9d1509c82c3efdeabbe1887c8c691bb8b7846c7da26e5f04b3c93c1cb79330bf867a37b0360888a607231b2a3d858fd7041f2e93bdc03c1e675c930b886d4aab97123247295f0d4fcc91d14e95594d096588d3cee1365450846f5e46c2eec02978de962882303996ba8557284b37ad5d8123c25e36c35c08b500b7d6d0fcf93ec06f");
        const result1 = ProofUtils.generateBigInteger(N, temp1);
        expect(bnToHexString(result1)).toEqual("cc6cc35fbff60d6eed86f5805f7b42d56082a5852b60c7feb8f8b925526493f4d1dd4d2a98e115591ee1310b815172daafc764ced0065599aed5b5cff2446d4fa0adf23ef56873560d9b2dfd43a15109273aad1e8af2b8b6c5bd760565511c127b56ca39c60cb9cb0d3739e72379e1b9a46a830c5454461357db7316d23db8dd09191c6112dd276482524be570b32500fd2efb738367decc43f8261d8cba40411a475d7e2c083e62b2d3172b730607beb162b276f32cfbe4c0c3b00a327eb90d2146c4dcd361a1981c8a2a6134ee859dbc49cf1da3bf290b81dffe6045148c0d950f043f1d17ac089cbb52eed10ec84ba10dc386daa8a9deac6235c7b6f89b61")

        const temp2 = bnFromHexString("51f9501998256c2e4b3e691dceaacd1d71786b06da6ba9bdce24d5d55a8db4c248bdf4065f93dae2287b0953aa3ff09ae99a26748fd7395cf68b2e2f17d07ff43672014d8059c5f971273f7faf328f1f75f61170f5f764614d12b7a12c437e1601d736e38a0bc8a56fcc87a102b12c9bd7b43623c32982835f5493613d42427bbd4c1298816499f5886ec641c9329e3de67f8b55498c02f5a82560f4ff8d726b3279f06107735ac3c66f74daf0cd084c250c4b7bb60b7ba26de402f28f102a7dbea65c53376f9a865efc6a327119f5d5e43e0d521884184655019ba178e838c43eb5b34ec4e4d5f9846a1237af0f7b9d220e7ff476245bf662d0d5d5f4a5f988");
        const result2 = ProofUtils.generateBigInteger(N, temp2);
        expect(bnToHexString(result2)).toEqual("9f0cdda6e791976754957dc6e697643ea272393de8fce8feb6b380b22b6995a5dc5786385cfbb72e65498c3031e4f157b11a0193841c4230092de414286c368780092122ed27a391bc73304bd9585018aa1a450710ce3e4ffa9df5d40f6c61485ae46e3764a4fc6289d219230723d3e883c7955862f2f73ec260283f6604249503c8b7943aca69814cce1efab51db799e4d9eceadf433d5577ae0809c4264c2ec4209b136ef5a1bcf25033b9f8684838b2aaae5798cdfff5228a0905f2de0e83b2b611e6948d6f765ab7c8178811d8902a4d48dc2a39747cf85c252af0a5fbc60706be5d1d382995d03637bec7c02dce36b358a90a85386a7dbd7dd6e25ac579")


        const temp3 = bnFromHexString("a50c8a3e43e7f362b952b0e095b62f55b966dcc552e1b12170e5ece8b7f00bf5e9696767116eb0a837712b155a43a9bca5f9b037d289adc5cbe27fe58f3228b835c8caa5b9ea5d3e966f558e1cd4447002a944326b45d2ec1ea99c6c7d43c1e6992ebbe807f393f2863c7d43dedc4a3fe1bc7d7d53bb862c3a6b572fdcad4d55b6ebd9aef2bc520a22efc1f097119383fb655b0614a62eaf689b5eeba7402f100a511028ca4a8c7483001a604faed6dbc0fa5d1c07f5ed3ef78557fc412e82969311a250a5fa24e8b65a93a035df05fdc2db7c739e68a63281483124301203339f4423cd729ab47d333ba09f58491d494ede9d790272a6f660178d8e585c5aae")
        const result3 = ProofUtils.generateBigInteger(N, temp3);
        expect(bnToHexString(result3)).toEqual(
            "1d29d6c61731e811da5d90f8d31f5c2190797c61017d7e12bfc904c7f52dc2b7febc4cf93ffd5dbedbb0a5d0892e92e164c2dc9d9099c53889a2caa60b6b50f04fa4491ac8d89cefac579e22ba7aba07ce412bfde577967eef25fb62b24c2aeb41257eb62385520be763c59908db1e2fa6e99ce2bc05315f6efd85cc44ff680963c9f4d1a1843abd49046db430bfb1088233955c648ef388fcb0ef5f7a80a8ad52e0c290f856a8c1bfd99f2576bb772615c0153de5e56aa2e6b7d3b83143f5b4c395a315bed81241c32faaa08c7beec0122da3db4800f345489cdd053608c93a458e792dc74f5ad53d0764f34c29ac65f1ac299b1bed304ef1344295d042666b"
        )
    })

    it('generatePaillierPublicKeyProof', async () => {

        const N = bnFromHexString("cf00f84055788480bcbf7eb13bdc0a0e37bcf4e5f4079f34dcae501c2e68958dd02e1cc71bf388e70413f0a7fc77467831f1e73e5dbe92bafccdcc07c632f118b601886b55bb6a524b7a1eb501d7f3f769624c55cabbd5b802e5d6127778116089adc2971356350afa0f00ce372c2efae914147e991bff5ec320ebb2e19c1eff2ea9b0f34104990bb126f830ffb1b1d98d1bd30cf6d2eea66d55f31ff3a8ff6b6f54579f862a74ce8f53a5e23815b21fd552dc55ad1cc3387831a360317c3529ec8eab177b67d4f8461a8c1d144ee9e243922a0b78a3c944fad80ea7eab637cb1b2cc64bf1e60c59e296cdbc765c71ab8353f64e72289d19d6ae4401ef90dd03")
        const P = bnFromHexString("dd779c589596ff36e156277c542432766af47d672c2fed1b140ba3d478232f02f695a1b63bf81c4cc2688fbf2ab50714166a4c9cf9dd44e1a951bc1b61aff86abccf1a5f97a8f7acd96f58358630eb524e20234809f8dc8c10fb0401e951cba7c7ebb9f42f7897ba8b8c0f8d694e054c27701e9a4f9a552e63f9a39b613debe9")
        const Q = bnFromHexString("ef4804373e2473431aeb44690311d96d1368173d821283936b44514bbe4f006544853f489c2adcef5a0c06c66087275d95d0f172090b8c9d94e66e97acc261356f7b8a279a2b45df4bb9da2e610df2cfae189cdd4769c0216b41ef8e8497cdd412ef6a94d2be91a798e26013143f683084c282f71f30e91af82fbbed24e7aa0b")
        let paillierPublicKeyProof = ProofUtils.generatePaillierPublicKeyProof(
            N,
            P,
            Q
        );

        const vo = paillierPublicKeyProof.toJson()
        expect(vo.n).toEqual("cf00f84055788480bcbf7eb13bdc0a0e37bcf4e5f4079f34dcae501c2e68958dd02e1cc71bf388e70413f0a7fc77467831f1e73e5dbe92bafccdcc07c632f118b601886b55bb6a524b7a1eb501d7f3f769624c55cabbd5b802e5d6127778116089adc2971356350afa0f00ce372c2efae914147e991bff5ec320ebb2e19c1eff2ea9b0f34104990bb126f830ffb1b1d98d1bd30cf6d2eea66d55f31ff3a8ff6b6f54579f862a74ce8f53a5e23815b21fd552dc55ad1cc3387831a360317c3529ec8eab177b67d4f8461a8c1d144ee9e243922a0b78a3c944fad80ea7eab637cb1b2cc64bf1e60c59e296cdbc765c71ab8353f64e72289d19d6ae4401ef90dd03")
        expect(vo.sigma.length).toEqual(11)
        expect(vo.sigma[0]).toEqual("ba4f4833aec72bb5938cc94c33af32cd22dde0ef4e98d18aea77f5f9fdab5d4f3484d1274e5bbbce0d45abdd74e2a038520712a0906e51147abc0eb383269ab9437da046a890c126c339914a68b7aeb8b1e933dbc740308e257668fd289d680bbb674bba4c30afdaa694e0521e6c643db7992ae516ffb0910d94da2d32d5eac4a2102b039f893023d46b43aff784d9eb643d7446783ff1d97c06febc89a5de893cfcbf5b2790f45a4d7200de03827dd665f61c26c19c2b686000e688e194beb2448873b9bb70c8cf2fcdf8814ebb56c94b2dcc68d90ad1e30d79105c7447609dee9987510d8ec71846819bbdcec876d825f7ef90cc4522beef45f1794b6688d4")
        expect(vo.sigma[10]).toEqual("b0ccb2bf639f6b22f2820640cc9a6ea6a22fcf0705ce3dfdea5aed75124124af88c27579f0f6e94e9ab2f5964d5d829c45654e6fd6e46720b4b7d1f3652501bf325ef1ea2a9fe3aacc7ac0550b3168cc35a7a2c92c908170308edcacf9ca0def602a352a2dcbc55b40e245538d50f820283bf8435d7781cd912bcb5c899efc63bf58720ff16bab9710bd90ffd54bc7317623c8183a44cfb127d2df9033d90e5afc13d3a6eedc4613edb187c4728ecdfc5d17a09dbbd787eb081edae5b86cd76f43c56e6377b91af37fa640b06978318967665792dbf2ffe3e36e022404536d73b1b5fcaf591cdc4568390bef3800462a3aecf9ddc66cc10bb173129e0fc2887c")


    })

    it('verifyPaillierPublicKeyProof', async () => {

        let p1KeyGen: KeyGeneration = new KeyGeneration("p1");

        let keyPair: PaillierKeyPair = await p1KeyGen.generatePaillierKeyPair();
        let paillierPrivateKey = keyPair.getPrivateKey();
        let N = paillierPrivateKey.getN();

        let paillierPublicKeyProof = ProofUtils.generatePaillierPublicKeyProof(
            N,
            paillierPrivateKey.getP(),
            paillierPrivateKey.getQ()
        );

        let verified = ProofUtils.verifyPaillierPublicKeyProof(paillierPublicKeyProof)
        expect(verified).toBeTruthy()
    })

})

