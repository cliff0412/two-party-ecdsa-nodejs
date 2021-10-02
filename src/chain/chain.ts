import BN from 'bn.js';
import { Transaction } from 'ethereumjs-tx';
import Web3 from 'web3';

import { SigningContextP1, SigningContextP2 } from '../protocols';

import { Signature, SignatureOnChain } from '../type';
import { ellipticUtil } from '../util';
import { sign } from '../../test/fixture/two-party-ecdsa';
import { CryptoConsants } from '../common/CryptoConstants';

const providerUrl =
  'https://kovan.infura.io/v3/b666e55354c042c589008dd116351623';
const web3 = new Web3(providerUrl);

export const recover = (msgHash: Buffer, sig: Signature): string => {
  return web3.eth.accounts.recover({
    messageHash: '0x' + msgHash.toString('hex'),
    v:
      '0x' +
      new BN(
        ellipticUtil.formSigVval(
          sig.recovery as number,
          CryptoConsants.CHAIN_NETWORK_ID_KOVAN,
        ),
        10,
      ).toString('hex'),
    r: '0x' + sig.r.toString('hex'),
    s: '0x' + sig.s.toString('hex'),
  });
};

export const sendTx = (
  from: string, // start with '0x'
  to: string, //start with '0x' ,
  signingContextP1: SigningContextP1,
  signingContextP2: SigningContextP2,
): Promise<any> => {
  return new Promise((resolve, reject) => {
    web3.eth
      .getTransactionCount(from)
      .then((nonce) => {
        // console.log('----nounce: ', nonce);

        const rawTx = {
          nonce: '0x' + nonce.toString(16),
          gasPrice: '0x174876E800',
          gasLimit: '0x7530',
          to: to, //
          value: '0x010000',
        };

        // ropsten， default: 'mainnet'
        // console.log('---start construct tx');
        const tx = new Transaction(rawTx, { chain: 'kovan' });

        const hash = tx.hash(false);

        const sig: Signature = sign(
          signingContextP1,
          signingContextP2,
          new BN(hash),
        );

        // TEMP ************************************************************ */
        const listOfVs = [0, 1];
        let recoverred = false;
        for (const vTemp of listOfVs) {
          sig.recovery = vTemp;
          if (recover(hash, sig) == from) {
            recoverred = true;
            break;
          }
        }
        if (!recoverred) {
          throw new Error('address not recoverred');
        }
        //************************************************************ */

        const sigOnChain: SignatureOnChain = {
          r: sig.r,
          s: sig.s,
          v: ellipticUtil.formSigVval(
            sig.recovery as number,
            CryptoConsants.CHAIN_NETWORK_ID_KOVAN,
          ),
        };

        tx.r = sigOnChain.r.toBuffer();
        tx.s = sigOnChain.s.toBuffer();
        tx.v = new BN(sigOnChain.v, 10).toBuffer();

        // console.log('---tx.raw---: ', tx.raw);

        const serializedTx = tx.serialize();

        web3.eth.defaultAccount = from;

        web3.eth
          .sendSignedTransaction('0x' + serializedTx.toString('hex'))
          .on('receipt', (receipt) => {
            // console.log(receipt);
            resolve(receipt);
          })
          .on('error', (err) => {
            // console.log('---- err in sendSignedTransaction ', err);
            reject(err);
          });
      })
      .catch((err) => {
        // console.log('error in get nounce: ', err);
        reject(err);
      });
  });
};
