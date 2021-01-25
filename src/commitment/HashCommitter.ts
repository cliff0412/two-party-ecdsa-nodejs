import crypto from 'crypto';

import { Commitment } from './Commitment';
import { CryptoException } from '../exception/CryptoException';


export class HashCommitter {

    public static getRandomBytes(): Buffer {
        // for security parameter k, the hash function output length is 2*k;
        // the random opening value is of length 3*k
        // byte[] r = new byte[BYTE_LENGTH / 2 * 3];
        // random.nextBytes(r);
        return crypto.randomBytes(48)
    }

    public static commit(r: Buffer, ...messageInHexStr: string[]): Commitment {
        if (messageInHexStr == null) {
            throw new Error(CryptoException.NULL_INPUT);
        }

        let md = crypto.createHash('sha256')

        // MessageDigest md = MessageDigest.getInstance("SHA-256");
        for (let msg of messageInHexStr) {
            if (msg == null) {
                throw new Error(CryptoException.NULL_INPUT);
            }
            md.update(msg, "hex");
        }
        md.update(r);

        return new Commitment(md.digest(), r);
    }

    public static verify(commitment: Commitment, ...messageInHexStr: string[]): boolean {
        if (commitment == null || commitment.getOpeningValue() == null
            || commitment.getCommitment() == null || messageInHexStr == null) {
            throw new Error(CryptoException.NULL_INPUT);
        }

        let md = crypto.createHash('sha256')
        for (let msg of messageInHexStr) {
            if (msg == null) {
                throw new Error(CryptoException.NULL_INPUT);
            }
            md.update(msg, 'hex');
        }

        md.update(commitment.getOpeningValue());

        return md.digest().equals(commitment.getCommitment());
    }
}