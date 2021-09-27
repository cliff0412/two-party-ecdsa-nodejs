import BN from 'bn.js';
import * as elliptic from 'elliptic';

import { ECPoint } from '../type/ECPoint';
import * as random from '../util/random';
import { CryptoConsants } from '../common/CryptoConstants';
import { CryptoException } from '../exception/CryptoException';
import { PaillierKeyPair } from '../paillier/PaillierKeyPair';
import PaillierKeyPairGenerator from '../paillier/PaillierKeyPairGenerator';

export class KeyGeneration {
  private ec: elliptic.ec;
  private party: string;

  public constructor(partyName: string) {
    this.ec = new elliptic.ec('secp256k1');
    this.party = partyName;
    // console.log(`key generation setup for ${this.party}`);
  }
  public generateEcdsaPrivateKeyShare(): BN {
    const N: BN = (this.ec as elliptic.ec).n as BN;
    return random.randBetween(CryptoConsants.ONE, N.div(new BN(3)));
  }

  public computeEcdsaPublicKeyShare(ecdsaPrivateKeyShare: BN): ECPoint {
    if (ecdsaPrivateKeyShare == null) {
      throw new Error(CryptoException.NULL_INPUT);
    }

    const subN: BN = ((this.ec as elliptic.ec).n as BN).div(new BN(3));
    if (
      ecdsaPrivateKeyShare.lt(CryptoConsants.ONE) ||
      ecdsaPrivateKeyShare.gt(subN)
    ) {
      throw new Error(CryptoException.PARAMETER_OUT_OF_RANGE);
    }
    return (this.ec as elliptic.ec).g.mul(ecdsaPrivateKeyShare);
  }

  public async generatePaillierKeyPair(): Promise<PaillierKeyPair> {
    const keyPairGenerator: PaillierKeyPairGenerator =
      new PaillierKeyPairGenerator(2048);
    return keyPairGenerator.generateKeyPair();
  }

  public computeEcdsaPublicKey(
    ecdsaPrivateKeyShare: BN,
    point: ECPoint,
  ): ECPoint {
    if (ecdsaPrivateKeyShare == null || point == null) {
      throw new Error(CryptoException.NULL_INPUT);
    }

    const upperBound: BN = (this.ec.n as BN).div(new BN(3));
    if (
      ecdsaPrivateKeyShare.lt(CryptoConsants.ONE) ||
      ecdsaPrivateKeyShare.gt(upperBound)
    ) {
      throw new Error(CryptoException.PARAMETER_OUT_OF_RANGE);
    }
    if (
      !point.validate()
      // || point.getCurve() != domainParams.getEcSpec().getCurve()
    ) {
      throw new Error(CryptoException.INFINITY_POINT);
    }

    return point.mul(ecdsaPrivateKeyShare);
  }
}
