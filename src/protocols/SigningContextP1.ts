import BN from 'bn.js';
import { bnToHexString, ecPointToJSON } from '../util/serialization';
import { bnFromHexString, ecPointFromJSON } from '../util/desearilization';
import { PaillierPrivateKey, PaillierPrivateKeyVO } from '../paillier';
import { ECDlogProof } from '../proof';
import { ECPoint, ECPointVO } from '../type';

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

  public equals(obj: SigningContextP1): boolean {
    if (obj == undefined || obj.getPaillierPrivateKey() == undefined) return false;

    return this.getPaillierPrivateKey().equals(obj.getPaillierPrivateKey()) &&
      this.getEcdsaPrivateKeyShare().eq(obj.getEcdsaPrivateKeyShare()) &&
      this.getEcdsaPublicKey().eq(obj.getEcdsaPublicKey())
  }

  public toJson(): SigningContextP1VO {
    return {
      paillierPrivateKey: this.getPaillierPrivateKey().toJson(),
      ecdsaPrivateKeyShare: bnToHexString(this.getEcdsaPrivateKeyShare()),
      ecdsaPublicKey: ecPointToJSON(this.getEcdsaPublicKey())
    }
  }

  public static fromJson(vo: SigningContextP1VO) {
    return new SigningContextP1(
      PaillierPrivateKey.fromJson(vo.paillierPrivateKey),
      bnFromHexString(vo.ecdsaPrivateKeyShare),
      ecPointFromJSON(vo.ecdsaPublicKey)
    )
  }
}

export type SigningContextP1VO = {
  /**
  * Paillier private key
  */
  paillierPrivateKey: PaillierPrivateKeyVO;
  /**
   * ECDSA private key share, x1
   */
  ecdsaPrivateKeyShare: string;
  /**
   * ECDSA public key, Q
   */
  ecdsaPublicKey: ECPointVO;
}