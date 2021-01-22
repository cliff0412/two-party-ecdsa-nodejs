import BN from 'bn.js';

import {
    Commitment
} from '../commitment'

import {
    PaillierPublicKey
} from '../paillier'

import {
    ECPoint
} from '../type'


export class SigningContextP2 {
    /**
       * P1's Paillier public key
       */
    private p1PaillierPublicKey: PaillierPublicKey;
    /**
     * encryption of P1's ECDSA private key under the Paillier public key
     */
    private p1EcdsaPrivateKeyShareEncryption: BN;
    /**
     * ECDSA private key share
     */
    private ecdsaPrivateKeyShare: BN;
    /**
     * ECDSA public key
     */
    private ecdsaPublicKey: ECPoint;
    /**
     * commitment of P1's ECDSA public random share
     */
    private p1Commitment: Commitment | null = null;
    /**
     * ECDSA private random share, k2
     */
    private ecdsaPrivateRandomShare: BN | null = null;

    public constructor(paillierPublicKey: PaillierPublicKey,
        p1EcdsaPrivateKeyShareEncryption: BN,
        ecdsaPrivateKeyShare: BN,
        ecdsaPublicKey: ECPoint) {
        this.p1PaillierPublicKey = paillierPublicKey;
        this.p1EcdsaPrivateKeyShareEncryption = p1EcdsaPrivateKeyShareEncryption;
        this.ecdsaPrivateKeyShare = ecdsaPrivateKeyShare;
        this.ecdsaPublicKey = ecdsaPublicKey;
    }

    public getP1PaillierPublicKey(): PaillierPublicKey {
        return this.p1PaillierPublicKey;
    }

    public getP1EcdsaPrivateKeyShareEncryption(): BN {
        return this.p1EcdsaPrivateKeyShareEncryption;
    }

    public getEcdsaPrivateKeyShare(): BN {
        return this.ecdsaPrivateKeyShare;
    }

    public getEcdsaPublicKey(): ECPoint {
        return this.ecdsaPublicKey;
    }

    public getP1Commitment(): Commitment {
        return this.p1Commitment as Commitment;
    }

    public setP1Commitment(p1Commitment: Commitment) {
        this.p1Commitment = p1Commitment;
    }

    public getEcdsaPrivateRandomShare(): BN {
        return this.ecdsaPrivateRandomShare as BN;
    }

    public setEcdsaPrivateRandomShare(ecdsaPrivateRandomShare: BN) {
        this.ecdsaPrivateRandomShare = ecdsaPrivateRandomShare;
    }
}