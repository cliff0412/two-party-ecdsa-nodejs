import '@babel/polyfill';
import PaillierKeyPairGenerator from './PaillierKeyPairGenerator';
import PaillierKeyPair from './PaillierKeyPair';
import * as bigintCryptoUtils from 'bigint-crypto-utils'
// const bigintCryptoUtils = require('bigint-crypto-utils/lib/index.browser.bundle.mod.js')
import * as util from '../util/util';


test('generateKeyPair', async () => {

    let paillierKeyPairGenerator: PaillierKeyPairGenerator = new PaillierKeyPairGenerator(2048);

    let keyPair: PaillierKeyPair= await  paillierKeyPairGenerator.generateKeyPair();
    // console.log(keyPair.getPrivateKey().getP().toString());
    
    expect(bigintCryptoUtils.isProbablyPrime(util.bnToBigInt(keyPair.getPrivateKey().getP()))).toBeTruthy();
    expect(bigintCryptoUtils.isProbablyPrime(util.bnToBigInt(keyPair.getPrivateKey().getQ()))).toBeTruthy();

})