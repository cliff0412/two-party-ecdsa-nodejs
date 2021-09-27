import BN from 'bn.js';
import { ECPoint } from '../type/ECPoint';
import { ECDlogProof } from '../proof/ECDlogProof';

export class KeyGenContextP1 {
  /**
   * P1's ECDSA private key share, x1
   */
  private ecdsaPrivateKeyShare: BN | null = null;
  /**
   * P1's ECDSA public key share, Q1
   */
  private ecdsaPublicKeyShare: ECPoint | null = null;
  /**
   * discrete logarithm proof of Q1
   */
  private Q1ECDlogProof: ECDlogProof | null = null;

  public constructor() {}

  public getEcdsaPrivateKeyShare(): BN {
    return this.ecdsaPrivateKeyShare as BN;
  }

  public setEcdsaPrivateKeyShare(ecdsaPrivateKeyShare: BN) {
    this.ecdsaPrivateKeyShare = ecdsaPrivateKeyShare;
  }

  public getEcdsaPublicKeyShare(): ECPoint {
    return this.ecdsaPublicKeyShare as ECPoint;
  }

  public setEcdsaPublicKeyShare(ecdsaPublicKeyShare: ECPoint) {
    this.ecdsaPublicKeyShare = ecdsaPublicKeyShare;
  }

  public getQ1ECDlogProof(): ECDlogProof {
    return this.Q1ECDlogProof as ECDlogProof;
  }

  public setQ1ECDlogProof(q1ECDlogProof: ECDlogProof) {
    this.Q1ECDlogProof = q1ECDlogProof;
  }
}
