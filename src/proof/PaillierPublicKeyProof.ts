import BN from 'bn.js';
import { bnToHexString } from '../util/serialization';

export class PaillierPublicKeyProof {
  public static NUMBER_OF_INSTANCES = 11;

  private N: BN;

  private sigma: BN[];

  public constructor(N: BN, sigma: BN[]) {
    this.N = N;
    this.sigma = sigma;
  }

  public getN(): BN {
    return this.N;
  }

  public getSigma() {
    return this.sigma;
  }

  public toJson(): PaillierPublicKeyProofVO {
    return {
      n: bnToHexString(this.N),
      sigma: this.sigma.map(s => bnToHexString(s))
    }
  }
}


export type PaillierPublicKeyProofVO = {
  n: string;
  sigma: string[];
}