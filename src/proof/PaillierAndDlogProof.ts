import BN from 'bn.js';
import { ECPoint } from 'src';
import { PaillierRangeProof } from './PaillierRangeProof';
import {PaillierZeroProof} from './PaillierZeroProof';

export class PaillierAndDlogProof {
    /**
       * ciphertext of r, where r in Z_{n/3}
       */
    private cr: BN;
    /**
     * ciphertext of rho, where rho in Z_{n^2}
     */
    private crho: BN;
    /**
     * R = [r]G
     */
    private R: ECPoint;
    /**
     * z = r + e*x + rho*n
     */
    private z: BN;
    /**
     * range proof of x \in Z_n for x \in Z_{n/3}
     */
    private xRangeProof: PaillierRangeProof;
    /**
     * range proof of r \in Z_n for r \in Z_{n/3}
     */
    private rRangeProof: PaillierRangeProof;
    /**
     * proof of cq encrypts 0
     */
    private cqZeroProof: PaillierZeroProof;

    public PaillierAndDlogProof(cr: BN, crho: BN, R: ECPoint, z: BN,
        xRangeProof: PaillierRangeProof, rRangeProof: PaillierRangeProof,
        cqZeroProof: PaillierZeroProof) {
        this.cr = cr;
        this.crho = crho;
        this.R = R;
        this.z = z;
        this.xRangeProof = xRangeProof;
        this.rRangeProof = rRangeProof;
        this.cqZeroProof = cqZeroProof;
    }

    public getCr(): BN {
        return this.cr;
    }

    public getCrho(): BN {
        return this.crho;
    }

    public getR(): ECPoint {
        return this.R;
    }

    public getZ(): BN {
        return this.z;
    }

    public getxRangeProof(): PaillierRangeProof {
        return this.xRangeProof;
    }

    public getrRangeProof(): PaillierRangeProof {
        return this.rRangeProof;
    }

    public getCqZeroProof(): PaillierZeroProof {
        return this.cqZeroProof;
    }
    public toJson(): PaillierAndDlogProofVO {
        throw Error("to be implemented")
    }
}


export type PaillierAndDlogProofVO = {

}