import BN from 'bn.js';
import { CryptoException } from '../exception/CryptoException';
import { bnToHexString } from '../util/serialization';
import { bnFromHexString } from '../util/desearilization';
export class PaillierPublicKey {
  private n: BN;
  private nSquare: BN;

  public constructor(n: BN) {
    if (n == null) {
      throw new Error(CryptoException.NULL_INPUT);
    }
    if (n.bitLength() < 2048) {
      throw new Error(CryptoException.BIT_LENGTH_TOO_SMALL);
    }
    if (n.isNeg()) {
      throw new Error(CryptoException.PARAMETER_TOO_SMALL);
    }

    this.n = n;
    this.nSquare = n.mul(n);
  }

  public getN(): BN {
    return this.n;
  }

  public getnSquare(): BN {
    return this.nSquare;
  }

  public toJson(): PaillierPublicKeyVO {
    return {
      n: bnToHexString(this.getN())
    }
  }

  public static fromJson(vo: PaillierPublicKeyVO): PaillierPublicKey {
    return new PaillierPublicKey(
      bnFromHexString(vo.n)
    )
  }
}

export type PaillierPublicKeyVO = {
  n: string;
}
