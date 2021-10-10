import { KeyGeneration, SigningContextP1 } from '.';
import { PaillierKeyPairGenerator } from '../paillier/PaillierKeyPairGenerator';
import { PaillierPrivateKey } from '../paillier/PaillierPrivateKey';

describe("SigningContextP1", () => {

    const generator = new PaillierKeyPairGenerator(2048);
    let privKey: PaillierPrivateKey;

    beforeAll(async () => {
        const keyPair = await generator.generateKeyPair();
        privKey = keyPair.getPrivateKey();
    })


    it("serialize and deserialize", async () => {

        const p1KeyGen: KeyGeneration = new KeyGeneration('p1');
        const x1 = p1KeyGen.generateEcdsaPrivateKeyShare();
        const Q = p1KeyGen.computeEcdsaPublicKeyShare(x1);
        const signCtxP1 = new SigningContextP1(privKey, x1, Q);

        const serializedSignCtxP1 = signCtxP1.toJson();
        const reconstructedSignCtxP1 = SigningContextP1.fromJson(serializedSignCtxP1);
        expect(reconstructedSignCtxP1.equals(signCtxP1)).toBeTruthy()
    })
})