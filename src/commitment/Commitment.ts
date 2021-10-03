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

  public toJson(): CommitmentVO {
    return {
      commitment: this.getCommitment().toString("hex"),
      openingValue: this.getOpeningValue().toString("hex")
    }
  }

  public static fromJson(vo: CommitmentVO): Commitment {
    return new Commitment(
      Buffer.from(vo.commitment, "hex"),
      Buffer.from(vo.openingValue, "hex")
    )
  }
}

export type CommitmentVO = {
  commitment: string;
  openingValue: string;
}