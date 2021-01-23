import BN from 'bn.js';
import elliptic from 'elliptic';
var minUtils = require('minimalistic-crypto-utils');
import { Signature } from '../type'

let EC = elliptic.ec;
var ec = new EC('secp256k1');

export const verifySig = (msg: BN, r: BN, s: BN, pubKey: Buffer) => {

    let sig = toDER({ r, s })
    // console.log("sig", sig)
    return ec.verify(msg, sig , pubKey)
}


const toDER = (sig: Signature) => {
    var r = sig.r.toArray();
    var s = sig.s.toArray();

    // Pad values
    if (r[0] & 0x80)
        r = [0].concat(r);
    // Pad values
    if (s[0] & 0x80)
        s = [0].concat(s);

    r = rmPadding(r);
    s = rmPadding(s);

    while (!s[0] && !(s[1] & 0x80)) {
        s = s.slice(1);
    }
    var arr = [0x02];
    constructLength(arr, r.length);
    arr = arr.concat(r);
    arr.push(0x02);
    constructLength(arr, s.length);
    var backHalf = arr.concat(s);
    var res = [0x30];
    constructLength(res, backHalf.length);
    res = res.concat(backHalf);
    return minUtils.encode(res);
}

function rmPadding(buf: any[]) {
    var i = 0;
    var len = buf.length - 1;
    while (!buf[i] && !(buf[i + 1] & 0x80) && i < len) {
        i++;
    }
    if (i === 0) {
        return buf;
    }
    return buf.slice(i);
}

function constructLength(arr: any[], len: number) {
    if (len < 0x80) {
        arr.push(len);
        return;
    }
    var octets = 1 + (Math.log(len) / Math.LN2 >>> 3);
    arr.push(octets | 0x80);
    while (--octets) {
        arr.push((len >>> (octets << 3)) & 0xff);
    }
    arr.push(len);
}