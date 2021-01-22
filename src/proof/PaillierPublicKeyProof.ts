import BN from 'bn.js';

export class PaillierPublicKeyProof {
    public static NUMBER_OF_INSTANCES: number = 11;

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
}