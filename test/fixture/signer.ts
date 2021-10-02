import { TransactionRequest } from '@ethersproject/abstract-provider';
import { arrayify, SignatureLike } from '@ethersproject/bytes';
import { keccak256 } from '@ethersproject/keccak256';
import { Deferrable } from '@ethersproject/properties';
import { serialize } from '@ethersproject/transactions';
import BN from 'bn.js';
import * as ethjsUtil from 'ethereumjs-util';
import { ethers, UnsignedTransaction } from 'ethers';
import { CryptoConsants } from '../../src/common/CryptoConstants';
import { PaillierPrivateKey } from '../../src/paillier/PaillierPrivateKey';
import { PaillierPublicKey } from '../../src/paillier/PaillierPublicKey';
import { SigningContextP1 } from '../../src/protocols/SigningContextP1';
import { SigningContextP2 } from '../../src/protocols/SigningContextP2';
import { KeyGenContextVO } from '../../src/type';
import Ganache from '../ganache';
import { sign } from './two-party-ecdsa';


export const signTransaction = async (
    transaction: Deferrable<TransactionRequest>,
    keyGenCtx: KeyGenContextVO
): Promise<string> => {
    const voidSigner = new ethers.VoidSigner(keyGenCtx.addressFromPoint, Ganache.provider);
    const populatedTx = await voidSigner.populateTransaction(transaction);
    // NODE: that's strange, but that's how etherjs implement. otherwise, it will throw error
    delete populatedTx.from;
    const digest = keccak256(serialize(<UnsignedTransaction>populatedTx));
    const msgHash = Buffer.from(arrayify(digest));

    const x1 = new BN(keyGenCtx.p1.x1, 'hex');
    const x2 = new BN(keyGenCtx.p2.x2, 'hex');
    const x = x1.mul(x2).mod(CryptoConsants.SECP256_CURVE_N);
    const Q = CryptoConsants.SECP256_CURVE_G.mul(x);
    const signingContextP1 = new SigningContextP1(
        new PaillierPrivateKey(
            new BN(keyGenCtx.p1.paillierPrivateKeyP, 'hex'),
            new BN(keyGenCtx.p1.paillierPrivateKeyQ, 'hex'),
        ),
        x1,
        Q,
    );

    const signingContextP2 = new SigningContextP2(
        new PaillierPublicKey(new BN(keyGenCtx.p2.paillierPublicKeyN, 'hex')),
        new BN(keyGenCtx.p2.cKey, 'hex'),
        x2,
        Q,
    );
    // hash of message to be signed
    const z = new BN(msgHash)

    const sig = sign(signingContextP1, signingContextP2, z);
    expect(sig.r.gt(CryptoConsants.ZERO));

    // const sig = await this.ecdsaSignService.ecdsaSign({
    //   msgHash: msgHash,
    //   keyIdentifiers: {
    //     publicKeyId: this.keyIdentifiers.publicKeyId,
    //     privateKeyId: this.keyIdentifiers.privateKeyId,
    //   },
    // });

    const recoverys = [0, 1];
    let v = 0;
    const chainId = populatedTx.chainId; //|| 1;
    let recoverred = false;
    for (const recovery of recoverys) {
        const v_test = chainId ? recovery + (chainId * 2 + 35) : recovery + 27;

        const pubKey = ethjsUtil.ecrecover(
            ethjsUtil.toBuffer(msgHash),
            v_test,
            sig.r.toBuffer(),
            sig.s.toBuffer(),
            chainId,
        );
        const addrBuf = ethjsUtil.pubToAddress(pubKey);
        const recoveredEthAddr = ethjsUtil.bufferToHex(addrBuf);
        if (keyGenCtx.addressFromPoint.toLowerCase() == recoveredEthAddr.toLowerCase()) {
            v = v_test;
            recoverred = true;
            break;
        }
    }

    if (!recoverred) {
        throw Error('signing eth address cannot be recoverred');
    }

    const signature: SignatureLike = {
        r: '0x' + new BN(sig.r).toString('hex'),
        s: '0x' + new BN(sig.s).toString('hex'),
        v: v,
    };
    const serilizedTx = serialize(<UnsignedTransaction>populatedTx, signature);

    return serilizedTx;
}

