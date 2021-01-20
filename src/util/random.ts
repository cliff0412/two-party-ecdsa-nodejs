import bigInteger, { BigInteger } from 'big-integer';
const cryptoUtil = require("./bigint-crypto-utils");

export const randomPrime = async (bitLength: number): Promise<BigInteger> => {
    console.log("using bigLength: ", bitLength)
    return new Promise((resolve, reject) => {
        cryptoUtil.prime(bitLength).then((primeNum: bigint) => {
            console.log(primeNum.toString())
            resolve(bigInteger(
                primeNum
            ))
        }).catch((err: any) => {
            reject(err)
        })


    });

}
