import BN from 'bn.js';
import { ECPoint } from '../type/ECPoint';
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
}
