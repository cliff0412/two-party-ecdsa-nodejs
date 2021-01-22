import {PaillierPublicKey} from './PaillierPublicKey';
import {PaillierPrivateKey} from './PaillierPrivateKey';

import { CryptoException } from "../exception/CryptoException";

export class PaillierKeyPair {
    private   publicKey: PaillierPublicKey;
    private   privateKey: PaillierPrivateKey;

    public constructor( publicKey: PaillierPublicKey,  privateKey: PaillierPrivateKey)  {
        if (publicKey == null || privateKey == null) {
            throw new Error(CryptoException.NULL_INPUT);
        }

        this.publicKey = publicKey;
        this.privateKey = privateKey;
    }

    public  getPublicKey() : PaillierPublicKey{
        return this.publicKey;
    }

    public  getPrivateKey(): PaillierPrivateKey {
        return this.privateKey;
    }
}