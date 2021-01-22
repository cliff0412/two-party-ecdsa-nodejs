import BN from 'bn.js'
import {Commitment} from '../commitment/Commitment';

export class KeyGenContextP2 {
    /**
     * P2's ECDSA private key share, x2
     */
    private ecdsaPrivateKeyShare: BN | null = null;
    /**
     * commitment of P1's ECDSA public key share
     */
    private commitment: Commitment | null = null;

    public constructor() { }

    public getEcdsaPrivateKeyShare() {
        return this.ecdsaPrivateKeyShare as BN;
    }

    public setEcdsaPrivateKeyShare(ecdsaPrivateKeyShare: BN) {
        this.ecdsaPrivateKeyShare = ecdsaPrivateKeyShare;
    }

    public getCommitment(): Commitment {
        return this.commitment as Commitment;
    }

    public setCommitment(commitment: Commitment) {
        this.commitment = commitment;
    }


}
