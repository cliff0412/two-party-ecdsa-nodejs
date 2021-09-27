import BN from 'bn.js';
import { PaillierPrivateKey } from '../paillier';

import { ECDlogProof } from '../proof';

import { ECPoint } from '../type';

export class SigningContextP1 {
  /**
   * Paillier private key
   */
  private paillierPrivateKey: PaillierPrivateKey;
  /**
   * ECDSA private key share, x1
   */
  private ecdsaPrivateKeyShare: BN;
  /**
   * ECDSA public key, Q
   */
  private ecdsaPublicKey: ECPoint;
  /**
   * ECDSA private random share, k1
   */
  private ecdsaPrivateRandomShare: BN | null = null;
  /**
   * ECDSA public random share, R1
   */
  private ecdsaPublicRandomShare: ECPoint | null = null;
  /**
   * discrete logarithm proof of R1
   */
  private R1ECDlogProof: ECDlogProof | null = null;
  /**
   * P2's ECDSA public random share, R2
   */
  private p2EcdsaPublicRandomShare: ECPoint | null = null;

  public constructor(
    paillierPrivateKey: PaillierPrivateKey,
    ecdsaPrivateKeyShare: BN,
    ecdsaPublicKey: ECPoint,
  ) {
    this.paillierPrivateKey = paillierPrivateKey;
    this.ecdsaPrivateKeyShare = ecdsaPrivateKeyShare;
    this.ecdsaPublicKey = ecdsaPublicKey;
  }

  public getPaillierPrivateKey(): PaillierPrivateKey {
    return this.paillierPrivateKey;
  }

  public getEcdsaPrivateKeyShare(): BN {
    return this.ecdsaPrivateKeyShare;
  }

  public getEcdsaPublicKey(): ECPoint {
    return this.ecdsaPublicKey;
  }

  public getEcdsaPrivateRandomShare(): BN {
    return this.ecdsaPrivateRandomShare as BN;
  }

  public setEcdsaPrivateRandomShare(ecdsaPrivateRandomShare: BN) {
    this.ecdsaPrivateRandomShare = ecdsaPrivateRandomShare;
  }

  public getEcdsaPublicRandomShare(): ECPoint {
    return this.ecdsaPublicRandomShare as ECPoint;
  }

  public setEcdsaPublicRandomShare(ecdsaPublicRandomShare: ECPoint) {
    this.ecdsaPublicRandomShare = ecdsaPublicRandomShare;
  }

  public getR1ECDlogProof(): ECDlogProof {
    return this.R1ECDlogProof as ECDlogProof;
  }

  public setR1ECDlogProof(r1ECDlogProof: ECDlogProof) {
    this.R1ECDlogProof = r1ECDlogProof;
  }

  public getP2EcdsaPublicRandomShare(): ECPoint {
    return this.p2EcdsaPublicRandomShare as ECPoint;
  }

  public setP2EcdsaPublicRandomShare(p2EcdsaPublicRandomShare: ECPoint) {
    this.p2EcdsaPublicRandomShare = p2EcdsaPublicRandomShare;
  }
}
