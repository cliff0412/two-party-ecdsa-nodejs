import KeyGenerationP1 from './KeyGenerationP1';

let keyGenerationP1: KeyGenerationP1 = new KeyGenerationP1();

test('generateEcdsaPrivateKeyShare', () => {
    let res = keyGenerationP1.generateEcdsaPrivateKeyShare();
    console.log(res.toString())
})


test('computeEcdsaPublicKeyShare', () => {

    let share = keyGenerationP1.generateEcdsaPrivateKeyShare();
    let res = keyGenerationP1.computeEcdsaPublicKeyShare(share);
    console.log(res.getX().toString())
    console.log(res.getY().toString())
})