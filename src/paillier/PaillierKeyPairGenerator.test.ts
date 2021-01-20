import '@babel/polyfill';
import PaillierKeyPairGenerator from './PaillierKeyPairGenerator';
import PaillierKeyPair from './PaillierKeyPair';


test('generateKeyPair', async () => {

    let paillierKeyPairGenerator: PaillierKeyPairGenerator = new PaillierKeyPairGenerator(2048);

    let keyPair: PaillierKeyPair= await  paillierKeyPairGenerator.generateKeyPair();
    // console.log(keyPair.getPrivateKey().getP().toString());
    
    expect(keyPair.getPrivateKey().getP().isPrime()).toBeTruthy();
    expect(keyPair.getPrivateKey().getQ().isPrime()).toBeTruthy();
})