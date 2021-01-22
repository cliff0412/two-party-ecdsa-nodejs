
import * as elliptic from 'elliptic';
import BN from 'bn.js'

import { ECPoint } from '../type';
import * as util from '../util/util'
import { HashCommitter } from './HashCommitter';

let ec = new elliptic.ec('secp256k1');
let g: ECPoint = ec.g;

let p1: ECPoint = g.mul(new BN(123456789))
let p2: ECPoint = g.mul(new BN("12345678987654321", 10))
let msg = [
    util.encodeCompressECpointToHexStr(g),
    util.encodeCompressECpointToHexStr(p1),
    util.encodeCompressECpointToHexStr(p2)
]

test('commit', () => {


    let commit = HashCommitter.commit(
        Buffer.from("7e729c29ebde09d46cfb11fa220b3f85d979c3d82c3de52046031db1fc1b14cf59e5ac429e253091c5d5ed54164ebc34", "hex"),
        ...msg
    )

    expect(commit.getCommitment().toString("hex")).toBe('e9f9bb362aadf87e9dadc6764a8e668b5e85b0dfd453e3011df6b4a39ed6c998')

    expect(commit.getOpeningValue().toString("hex")).toBe('7e729c29ebde09d46cfb11fa220b3f85d979c3d82c3de52046031db1fc1b14cf59e5ac429e253091c5d5ed54164ebc34')

})

test.only('verify', () => {
    let commit = HashCommitter.commit(
        HashCommitter.getRandomBytes(),
        ...msg
    )

    let res = HashCommitter.verify(commit, ...msg)

    expect(res).toBeTruthy()
})