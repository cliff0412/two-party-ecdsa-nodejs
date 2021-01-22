export class Commitment {

    private commitment: Buffer;
    private openingValue: Buffer;

    public constructor(commitment: Buffer, openingValue: Buffer) {
        this.commitment = commitment;
        this.openingValue = openingValue;
    }

    public getCommitment() {
        return this.commitment;
    }

    public getOpeningValue() {
        return this.openingValue;
    }


}