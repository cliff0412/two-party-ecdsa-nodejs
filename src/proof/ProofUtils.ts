import BN from 'bn.js';

import { ECDlogProof } from './ECDlogProof';
import { ECPoint } from '../type';
import { CryptoException } from '../exception/CryptoException';
import { CryptoConsants } from '../common/CryptoConstants';
import { PaillierPublicKeyProof } from './PaillierPublicKeyProof';

import * as elliptic from 'elliptic';
import * as random from '../util/random';
import crypto from 'crypto';
import { bnToHexString } from '../util/serialization';

export class ProofUtils {
  public static ec = new elliptic.ec('secp256k1');

  /**
   * Generates proof that N is a valid Paillier public key, i.e., gcd(N,phi(N))=1.
   * 1. Ninv = N^{-1} mod phi(N)
   * 2. seed = Hash(N)
   * 3. use seed to initialize ctr_aes
   * 4. for i in {1,...,11} do
   *        r_i = enc(0...0) mod N
   *        sigma_i = (r_i)^Ninv mod N
   * 5. proof pi = (sigma_1,...,sigma_11)
   *
   * To verify pi, check that if all sigma_i satisfy:
   *     (sigma_i)^N mod N = r_i mod N
   *
   * @param N the Paillier modulus
   * @param p one of the primes
   * @param q the other prime
   * @return a Paillier public key proof
   */
  public static generatePaillierPublicKeyProof(
    N: BN,
    p: BN,
    q: BN,
  ): PaillierPublicKeyProof {
    if (N == null || p == null || q == null) {
      throw new Error(CryptoException.NULL_INPUT);
    }
    if (N.isNeg()) {
      throw new Error(CryptoException.PARAMETER_TOO_SMALL);
    }

    const phi: BN = p.sub(CryptoConsants.ONE).mul(q.sub(CryptoConsants.ONE));
    let NInv: BN;
    try {
      const nInRed = N.toRed(BN.red(phi));
      NInv = nInRed.redInvm();
    } catch (e) {
      throw new Error(CryptoException.INCONSISTENT_INPUTS + JSON.stringify(e));
    }

    const sigma: BN[] = [];

    PaillierPublicKeyProof.NUMBER_OF_INSTANCES;
    let temp: BN = N;

    // ATTENTION
    const NInvFromRed = (NInv as any).fromRed();
    for (let i = 0; i < PaillierPublicKeyProof.NUMBER_OF_INSTANCES; i++) {
      temp = this.generateBigInteger(N, temp);

      const tempInRed = temp.toRed(BN.red(N));
      try {
        sigma[i] = tempInRed.redPow(NInvFromRed);
      } catch (err) {
        console.error('----------error-------', err);
        throw new Error(CryptoException.RED_POW_ERROR);
      }
    }

    return new PaillierPublicKeyProof(N, sigma);
  }

  /**
   * Verifies Paillier public key proofs.
   * 1. Ninv = N^{-1} mod phi(N)
   * 2. seed = Hash(N)
   * 3. use seed to initialize ctr_aes
   * 4. for i in {1,...,11} do
   *        r_i = enc(0...0) mod N
   *        sigma_i = (r_i)^Ninv mod N
   * 5. proof pi = (sigma_1,...,sigma_11)
   *
   * To verify pi, check that if all sigma_i satisfy:
   *     (sigma_i)^N mod N = r_i mod N
   *
   * @param proof the proof
   * @return true if the verification passed, else false
   */
  public static verifyPaillierPublicKeyProof(
    proof: PaillierPublicKeyProof,
  ): boolean {
    if (proof == null) {
      throw new Error(CryptoException.NULL_INPUT);
    }

    const sigma = proof.getSigma();
    const N = proof.getN();

    if (sigma == null || N == null) {
      throw new Error(CryptoException.NULL_INPUT);
    }
    if (sigma.length != PaillierPublicKeyProof.NUMBER_OF_INSTANCES) {
      throw new Error(CryptoException.INVALID_LENGTH);
    }
    if (N.isNeg()) {
      throw new Error(CryptoException.PARAMETER_TOO_SMALL);
    }

    let temp = N;
    for (let s of sigma) {
      if (s == null) {
        throw new Error(CryptoException.NULL_INPUT);
      }
      temp = ProofUtils.generateBigInteger(N, temp);

      s = (s as any).fromRed();
      const sInRed = s.toRed(BN.red(N));
      const sPowN = sInRed.redPow(N);

      if (!sPowN.eq(temp)) {
        return false;
      }
    }

    return true;
  }

  /**
   * Generates a elliptic curve discrete logarithm proof.
   * @param G the base point of the curve
   * @param P the public point
   * @param x the private integer, such that P=[x]G
   * @return an ECDlogProof
   */
  public static generateECDlogProof(
    // G: ECPoint,
    P: ECPoint,
    x: BN,
  ): ECDlogProof {
    const G = this.ec.g;
    if (G == null || P == null || x == null) {
      throw new Error(CryptoException.NULL_INPUT);
    }
    if (G.isInfinity()) {
      throw new Error(CryptoException.INFINITY_POINT);
    }

    const n: BN = this.ec.curve.n;

    const k: BN = random.randBetween(
      CryptoConsants.ONE,
      n.sub(CryptoConsants.ONE),
    );
    const X: ECPoint = G.mul(k);

    // e = Hash(G, P, X) mod n
    const e: BN = this.computeChallenge(n, G, P, X);
    const z: BN = k.add(e.mul(x)).mod(n);

    return new ECDlogProof(P, X, z);
  }

  /**
   * Verifies that an elliptic curve discrete logarithm proof.
   * @param proof the ec discrete logarithm proof
   * @param G the base point
   * @return true if the verification passed, else false
   */
  public static verifyECDlogProof(
    proof: ECDlogProof,
    // G: ECPoint
  ): boolean {
    const G = this.ec.g;
    if (proof == null || G == null) {
      throw new Error(CryptoException.NULL_INPUT);
    }
    if (G.isInfinity()) {
      throw new Error(CryptoException.INFINITY_POINT);
    }

    const n: BN = this.ec.n as BN;
    const e: BN = this.computeChallenge(n, G, proof.getQ(), proof.getX());

    return G.mul(proof.getZ()).eq(proof.getX().add(proof.getQ().mul(e)));
  }

  /**
   * Computes a challenge value modulo a modulus from elliptic curve points.
   * @param m the modulus
   * @param points the elliptic curve points
   * @return a challenge value modulo m
   */
  public static computeChallenge(m: BN, ...points: ECPoint[]): BN {
    const md = crypto.createHash('sha256');
    for (const point of points) {
      if (point == null) {
        throw new Error(CryptoException.NULL_INPUT);
      }
      md.update(Buffer.from(point.encodeCompressed('hex'), 'hex'));
    }
    const hash: Buffer = md.digest();
    // console.log("-hased output-: ", hash)
    return this.hashToInt(hash.toString("hex"), m);
  }

  /**
   * Converts a hash value to integer modulo a modulus.
   * @param hash the hash value
   * @param m the modulus
   * @return an integer modulo m
   */
  public static hashToInt(hashInHex: string, m: BN): BN {
    if (hashInHex == '' || m == null) {
      throw new Error(CryptoException.NULL_INPUT);
    }
    if (m.isNeg()) {
      throw new Error(CryptoException.PARAMETER_TOO_SMALL);
    }

    let t: BN;
    try {
      t = new BN(hashInHex, 16);
    } catch (e) {
      throw new Error(CryptoException.INVALID_LENGTH);
    }

    return t.mod(m);
  }

  /**
   * Computes a challenge value modulo a modulus from an integer.
   * @param m the modulus
   * @param in the integer
   * @return a challenge value modulo m
   */
  private static generateBigInteger(m: BN, in_val: BN): BN {
    if (m == null || in_val == null) {
      throw new Error(CryptoException.NULL_INPUT);
    }

    let md = crypto.createHash('sha256');

    let num = (m.bitLength() + 7) / 8;
    const out = new ArrayBuffer(num);
    const out_view = new Uint8Array(out);

    let temp = in_val.toBuffer();
    let count = 0;
    while (num >= 32) {
      // 32 is the digest length in bytes
      md.update(temp);
      temp = md.digest();

      // System.arraycopy(temp, 0, out, count, 32);

      for (let i = 0; i < 32; i++) {
        out_view[count + i] = temp[i];
      }

      num -= 32;
      count += 32;
      md = crypto.createHash('sha256');
    }
    if (num > 0) {
      md.update(temp);
      temp = md.digest();
      // System.arraycopy(temp, 0, out, count, num);
      for (let i = 0; i < 32; i++) {
        out_view[count + i] = temp[i];
      }
    }

    return this.hashToInt(Buffer.from(out_view).toString('hex'), m);
  }
}
