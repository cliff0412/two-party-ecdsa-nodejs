import BN from 'bn.js';

import { CryptoConsants } from '../common/CryptoConstants';
import { CryptoException } from '../exception/CryptoException';

import { SigningContextP2 } from './SigningContextP2';
import { PaillierPublicKey, Paillier } from '../paillier';
import { ECPoint } from '../type';

import { random } from '../util';

export class SigningP2 {
  /**
   * ECDSA private key share
   */
  private ecdsaPrivateKeyShare: BN;
  /**
   * ECDSA public key
   */
  private ecdsaPublicKey: ECPoint;
  /**
   * Paillier public key of P1
   */
  private p1PaillierPublicKey: PaillierPublicKey;
  /**
   * Paillier encryption of P1's ECDSA private key share
   */
  private p1EcdsaPrivateKeyShareEncryption: BN;

  public constructor(context: SigningContextP2) {
    if (
      context == null ||
      context.getEcdsaPrivateKeyShare() == null ||
      context.getEcdsaPublicKey() == null ||
      context.getP1PaillierPublicKey() == null ||
      context.getP1EcdsaPrivateKeyShareEncryption() == null
    ) {
      throw new Error(CryptoException.NULL_INPUT);
    }

    this.ecdsaPrivateKeyShare = context.getEcdsaPrivateKeyShare();
    this.ecdsaPublicKey = context.getEcdsaPublicKey();
    this.p1PaillierPublicKey = context.getP1PaillierPublicKey();
    this.p1EcdsaPrivateKeyShareEncryption =
      context.getP1EcdsaPrivateKeyShareEncryption();
  }

  public generatePrivateRandomShare(): BN {
    const n = CryptoConsants.SECP256_CURVE_N;
    return random.randBetween(CryptoConsants.ONE, n.sub(CryptoConsants.ONE));
  }

  public computePublicRandomShare(privateRandomShare: BN): ECPoint {
    return CryptoConsants.SECP256_CURVE_G.mul(privateRandomShare);
  }

  public computePublicRandom(
    privateRandomShare: BN,
    p1PublicRandomShare: ECPoint,
  ): ECPoint {
    return p1PublicRandomShare.mul(privateRandomShare);
  }

  public computeC3(z: BN, r: BN, privateRandomShare: BN): BN {
    if (z == null || r == null) {
      throw new Error(CryptoException.NULL_INPUT);
    }
    if (
      z.lt(CryptoConsants.ZERO) ||
      z.bitLength() > CryptoConsants.SECP256_CURVE_N.bitLength()
    ) {
      throw new Error(CryptoException.PARAMETER_OUT_OF_RANGE);
    }
    if (r.lt(CryptoConsants.ONE) || r.gte(CryptoConsants.SECP256_CURVE_N)) {
      throw new Error(CryptoException.PARAMETER_OUT_OF_RANGE);
    }

    const n = CryptoConsants.SECP256_CURVE_N;

    const rho = random.randBetween(
      CryptoConsants.ONE,
      n.mul(n).sub(CryptoConsants.ONE),
    );

    const k2Inv = privateRandomShare.toRed(BN.red(n)).redInvm();
    const c1 = Paillier.encrypt(
      this.p1PaillierPublicKey,
      rho.mul(n).add(k2Inv.mul(z).mod(n)),
    );

    const v = k2Inv.mul(r).mul(this.ecdsaPrivateKeyShare).mod(n);
    const c2 = Paillier.multiply(
      this.p1PaillierPublicKey,
      this.p1EcdsaPrivateKeyShareEncryption,
      v,
    );

    return Paillier.add(this.p1PaillierPublicKey, c1, c2);
  }

  public getEcdsaPublicKey() {
    return this.ecdsaPublicKey;
  }
}
