import BN from 'bn.js';


import * as ellipticUtil from './ellipticUtil';

test('verifySig true', () => {

    let msg: BN = new BN("34859b3dd34d9d55e7591f419c6d7e91c12e913d1a814fd0e6e71694da263103", "hex")

    let r: BN = new BN("13df7959887e23c5fc4bc3db5788ca735dfb435eadec83002c158e4c32a589c4", "hex")

    let s: BN = new BN("197caa74326a42c931736a07f72aa876cd9490cc7b14c7acd756262977ae1003", "hex")

    let res = ellipticUtil.verifySig(msg, r, s, Buffer.from("0217f03cb89fd78347e528127621355696752ca398a2c6a4dacbdcb8ebefd9b4d7", "hex"))

    // console.log('----res---- ', res)

    expect(res).toBeTruthy()
})

test('verifySig true', () => {

    let msg: BN = new BN("34859b3dd34d9d55e7591f419c6d7e91c12e913d1a814fd0e6e71694da263101", "hex")

    let r: BN = new BN("13df7959887e23c5fc4bc3db5788ca735dfb435eadec83002c158e4c32a589c4", "hex")

    let s: BN = new BN("197caa74326a42c931736a07f72aa876cd9490cc7b14c7acd756262977ae1003", "hex")

    let res = ellipticUtil.verifySig(msg, r, s, Buffer.from("0217f03cb89fd78347e528127621355696752ca398a2c6a4dacbdcb8ebefd9b4d7", "hex"))

    // console.log('----res---- ', res)

    expect(res).toBeFalsy()
})

test('privateKeyToAccount', () => {
    let addr = ellipticUtil.privateKeyToAccountAddress("16ea9a15dd4381a2ea9c41531fee530e6a78dadc1a86d3e64f207c35f4be1d17")
    expect(addr).toBe("0x00D8d0660b243452fC2f996A892D3083A903576F")


    let addr2 = ellipticUtil.privateKeyToAccountAddress("e2b253cee5a710074c1a93588deed9c51d470ac894a78e793502d392c689c7b7")
    console.log("address is: ", addr2)
})