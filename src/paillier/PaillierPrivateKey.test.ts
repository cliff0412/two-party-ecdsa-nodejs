import {PaillierKeyPairGenerator} from './PaillierKeyPairGenerator';
import {PaillierPrivateKey} from './PaillierPrivateKey';

describe("paillier private key", () => {

    const generator = new PaillierKeyPairGenerator(2048);
    let privKey: PaillierPrivateKey;

    beforeAll( async () => {
        const keyPair = await generator.generateKeyPair();
        privKey = keyPair.getPrivateKey();
    })


    it("serialization and deserialization", () => {
       const serailizaedPrivKey = privKey.toJson();
       const reconstructedPrivKey = PaillierPrivateKey.fromJson(serailizaedPrivKey);
       expect(reconstructedPrivKey.equals(privKey)).toBeTruthy()
    })
})