import bigInteger, { BigInteger } from 'big-integer';
const cryptoUtil = require("./bigint-crypto-utils");

export const randomPrime = async (bitLength: number): Promise<BigInteger> => {
    console.log("using bigLength in randomPrime: ", bitLength)
    return new Promise((resolve, reject) => {
        console.log("cryptoUtil: ", cryptoUtil)
        cryptoUtil.prime(bitLength).then((primeNum: bigint) => {
            console.log("generated random prime: ",primeNum.toString())
            resolve(bigInteger(
                primeNum
            ))
        }).catch((err: any) => {
            console.log("error in randomPrime ", err)
            reject(err)
        })


    });

}
