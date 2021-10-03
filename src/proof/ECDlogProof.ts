import BN from 'bn.js';
import { ECPoint, ECPointVO } from '../type/ECPoint';
import { ecPointToJSON, bnToHexString } from '../util/serialization';
import { ecPointFromJSON, bnFromHexString } from '../util/desearilization';

/**
 * to proof x is a discrete log of Q
 */
export class ECDlogProof {
  /**
   * the public point to be proved: Q=[x]G
   */
  private Q: ECPoint;
  /**
   * random point: X=[k]G for random k
   */
  private X: ECPoint;
  /**
   * the second message sent by prover in sigma protocol: z=k+ex, e=Hash(G,Q,X)
   */
  private z: BN;

  public constructor(Q: ECPoint, X: ECPoint, z: BN) {
    this.Q = Q;
    this.X = X;
    this.z = z;
  }

  public getQ(): ECPoint {
    return this.Q;
  }

  public getX(): ECPoint {
    return this.X;
  }

  public getZ(): BN {
    return this.z;
  }

  public toJson(): ECDlogProofVO {
    return {
      q: ecPointToJSON(this.getQ()),
      x: ecPointToJSON(this.getX()),
      z: bnToHexString(this.getZ())
    }
  }

  public static fromJson(vo: ECDlogProofVO): ECDlogProof {
    return new ECDlogProof(
      ecPointFromJSON(vo.q),
      ecPointFromJSON(vo.x),
      bnFromHexString(vo.z)
    )
  }
}

export type ECDlogProofVO = {
  q: ECPointVO;
  x: ECPointVO;
  z: string;
}