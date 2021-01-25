import BN from 'bn.js';

import * as elliptic from 'elliptic';
import { ECPoint } from '../type';

let ec = new elliptic.ec('secp256k1');

export class CryptoConsants {

    public static PARTY_ONE: string = "p1";
    public static PARTY_TWO: string = "p2";

    public static ONE: BN = new BN(1);
    public static ZERO: BN = new BN(0);


    public static SECP256_CURVE_N: BN = ec.n as BN;
    public static SECP256_CURVE_G: ECPoint = ec.g;

    public static CHAIN_NETWORK_ID_MAIN: number = 1;
    public static CHAIN_NETWORK_ID_KOVAN: number = 42;
}