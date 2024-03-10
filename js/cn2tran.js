"use sctrict";

cn2tran = {

// ===== TransportEnDe library ======
// supported data_modes:
// 0 - binary or undefined
// 1 - utf-8
// 2 - ascii (all charcodes < 128)
// 3 - utf-8 in cp1251 (ascii + cyr)
//   transport encodes:
// 4 - base64
// 5 - base64url
// 6 - hex
// 7 - vc85
// 8 - base6400
// 9 - reserved
//10 - file with meta-data

encode_by_data_mode: function(data_mode, data) {
    switch (data_mode) {
        case 1:
            return cn2conv.buff2str(data);
        case 2:
            return cn2conv.buff2str(data, 0);
        case 3:
            return this.arr1251_to_utf8str(data);
        case 4: // base64-classic
            return this.base64_encode(data, false);
        case 5: // base64-url
            return this.base64_encode(data, true);
        case 6: // hex
            return this.hex_encode(data);
        case 7: // vc85
            return this.vc85_encode(data);
        case 8: // base6400
            return this.base6400_encode(data);
        default:
            return cn2conv.toUint8Array(data);
    }
},

decode_by_data_mode: function(data_mode, data) {
    switch (data_mode) {
        case 0: // binary mode
        case 1: // utf-8 - php string is already encoded to utf-8
        case 2: // ASCII- php string already in ascii
            return data;
        case 3: // convert from utf-8 to cp1251
            return this.utf8_to_cp1251(data);
        case 4: // base64-classic
            return this.base64_decode(data, false);
        case 5: // base64-url
            return this.base64_decode(data, true);
        case 6: //hex
            return this.hex_decode(data);
        case 7: // to vc85 over utf-8
            return this.vc85_decode(data, false, true);
        case 8: // base6400 over utf-8
            return this.base6400_decode(data);
        default: // unknown data-mode
            return false;
    }
},

data_mode_detect: function(str) {
    let dt = this.transportDetect(str);
    if (dt === false) return false;
    // get chars range (min, max)
    let back, buff=dt[1], min=dt[2], max = dt[3];

    if (dt[0] > 0) {
        // back = this.encode_by_data_mode(dt[0], dt[1]);
        return [dt[0], buff]; // detected transport encode: 4-base64c, 5-base64u, 6-hex, 7-vc85, 8-base6400
    }


    // try ascii
    if (min < 47 && max < 128) {
        return [2, buff]; // detected ascii range
    }

    // try cp1251 over unicode
    if (max > 1024 && max < 1116) {
        buff = this.utf8str_to_arr1251(str, true);
        if (buff !== false) {
            back = this.arr1251_to_utf8str(buff);
            if (back === str) {
                return [3, buff.buffer]; // detected cp1251 chars
            }
        }
    }

    // fallback to utf-8
    return [1, cn2conv.str2buff(str)];
},

transportDetectQuick: function(str, only_header=false) {
    let l;
    if (str instanceof ArrayBuffer) {
        l = str.byteLength;
    } else if (typeof str.length === 'undefined') {
        return false;
    } else {
        l = str.length;
    }
    if (l > 60) l = 60;
    let i, bv = [];
    if (str instanceof ArrayBuffer) {
        bv = str.slice(0, l);
    } else {
        for (i = 0; i < l; i++) {
            bv.push((typeof str === 'string') ? str.charCodeAt(i) : str[i]);
        }
    }
    let dt = this.transportDetect(bv);
    if (!dt[0]) {
        return false;
    }
    if (only_header) {
        return dt;
    }
    return this.transportDetect(str);
},

/**
 * Detect transport encodings:
 * 0 - binary or undefined  
 * 4 - base64
 * 5 - base64url
 * 6 - hex
 * 7 - vc85
 * 8 - base6400
 * return example: [data_mode, buff, min, max]
 * 
 * @param {string|array} str 
 */
transportDetect: function (str) {

    // calculate chars range (min, max) and charr array
    let l, i, c, tmp, back, max=0, min = 9999999, bv = [];

    if (str instanceof ArrayBuffer) {
        str = Array.from(new Uint8Array(str));
    }
    if (typeof str.length === 'undefined') {
        return false; // bad data type
    }
    l = str.length;
    if (typeof str === 'string') {
        for (i = 0; i < l; i++) {
            c = str.charCodeAt(i);
            if (c > max) max = c;
            if (c < min) min = c;
            bv.push(c);
        }
    } else if (Array.isArray(str)) {
        for (i = 0; i < l; i++) {
            c = str[i];
            if (c > max) max = c;
            if (c < min) min = c;
            bv.push(c);
        }
    } else {
        return false; // bad source data
    }
    if (!i) {
        return false; // no source data
    }
    // make back str from bv-array (if need)
    if (typeof str !== 'string') {
        str = String.fromCharCode.apply(null, bv);
    }

    // may be hex, base64-classic, base64url
    if (min > 42 && max < 123 && (l % 2 === 0)) {
        
        // try hex-lowercase
        if (min > 47 && max < 103) {
            tmp = this.hex_decode(str);
            if (tmp !== false) {
                if (!l) return [0, tmp, 0, 0];
                // only hex-lowercase accepted
                back = this.hex_encode(tmp);
                if (back === str) {
                    return [6, tmp, min, max]; // detected hex-lowercase
                }
            }
        }

        // try base64 classic/url modes
        var tlen = -2 + 0.75 * l;  // min target length for base64-modes
        if (min > 42 && max < 123 && tlen > 0 && ((l % 4) === 0)) {
            // try unpack base64-classic
            back = this.base64_decode(str, false);
            if (back && back.byteLength >= tlen) {
                // try pack back
                tmp = this.base64_encode(back, false);
                if (str === tmp) {
                    return [4, back, min, max]; // detected base64-classic
                }
            }

            // try unpack base64-url
            back = this.base64_decode(str, true);
            if (back && back.byteLength >= tlen) {
                // try pack back
                tmp = this.base64_encode(back, true);
                if (str === tmp) {
                    return [5, back, min, max]; // detected base64url
                }
            }
        }

    } else if (min > 47 && max < 1103 && max > 1039) {
        // may be vc85 over unicode
        tmp = this.vc85_decode(str, true, false);
        if (tmp !== false) {
            back = this.vc85_encode(tmp, true);
            if (Array.isArray(str)) {
                str = String.fromCharCode.apply(null, str);
            }
            if (str === back) {
                return [7, tmp.buffer, min, max];
            }
        }
    } else if (min > 47 && max < 255) {
        // may be vc85 in bytes
        tmp = this.vc85_decode(bv, false, false);
        if (tmp !== false) {
            back = this.vc85_encode(tmp, false);
            i = bv.length;
            if ((i === back.length) && (back[i-1] === bv[i-1])) {
                return [7, tmp.buffer, min, max];
            }
        }
    } else if (min > 13311 && max < 17473) { // && !(l % 3) && !(l % 6)) {
        tmp = this.base6400_decode(str);
        if (tmp !== false) {
            back = this.base6400_encode(tmp);
            if (back === str) {
                return [8, tmp, min, max];
            }
        }
    }

    return [0, (new Uint8Array(bv)).buffer, min, max];
},

// ========== Encoders and decoders ===========
// Supported: base64, base64url, vc85, base6400

// base64 chars without last 2
b64s: "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789",

// prepare vc85 chars-arrays
vc85chars: (str => {
    let i, v, c = 48, out = new Uint8Array(85), back = new Uint8Array(256);
    for(i=0;i<85;i++) {
        out[i] = c;
        back[c] = i + 1;
        v = parseInt(str[i]);
        c += v ? v : 71;
    }
    return [out, back];
})('111111111811111112111121111111111711111111112111111111111102122345211614121134521151'),
//'0123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyzБГДЖИЛПФЦЧШЮЯгджзилпфцчшэю' 

vc85_encode: function(data, out_utf8str = true) {

    // convert source to ArrayBuffer
    let buff = cn2conv.in2buff(data);

    // parameters calculation
    let l = buff.byteLength,
        dview = new DataView(buff),
        gcnt = Number(Math.floor(l / 4)), // how many 5-bytes groups in out
        last_a = 4 - l % 4, // code of last group length: 1 (3 byte), 2 (2 byte), 3 (1 byte), 4 (empty)
        bc = this.vc85chars[0], // vc85 chars array
        p, dv, i, r, dec, wr;

    // create output array
    let out = new Uint8Array(gcnt * 5 + ((l % 4) ? (1 + l % 4) : 0));
    
    // read last group to ld32 Uint32
    let ld32 = 0;
    for (rd = gcnt * 4; rd < l; rd++) {
        ld32 = ld32 << 8;
        ld32 += dview.getUint8(rd);
    }

    // encoding
    for (g = 0; g <= gcnt; g++) {
        wr = 4 + g * 5;
        rd = g * 4;
        if (g < gcnt) {
            // read 4 bytes
            dec = dview.getUint32(rd);
        } else {
            dec = ld32;
            if (last_a === 4) break;
            wr -= last_a;
        }
        while (dec > 0) {
            dv = Math.floor(dec / 85);
            i = dec % 85;
            dec = dv;
            out[wr--] = bc[i];
        }
    }
    out = out.map(v => v ? v : 48); // replace 0 to 48
    if (out_utf8str) {
        return this.arr1251_to_utf8str(out);
    }
    return out;
},

vc85_decode: function (data, utf8_str_in = true, utf8_str_out = true) {
    let buff, c, p, dv, i, r, dec, wr, bc = this.vc85chars[1];
    if (Array.isArray(data)) {
        data = String.fromCharCode.apply(null, data);
    }
    if (typeof data === 'string') {
        if (utf8_str_in) {
            buff = this.utf8str_to_arr1251(data).buffer;
        } else {
            buff = cn2conv.str2buff(data);
        }
    } else if (data instanceof ArrayBuffer) {
        buff = data;
    } else {
        buff = cn2conv.toUint8Array(data);
        if (typeof buff.buffer === 'undefined') {
            return false;
        }
        buff = buff.buffer;
    }

    let l = buff.byteLength,
    dview = new DataView(buff),
    gcnt = Number(Math.floor(l / 5)), // how many full-4-bytes groups in out
    last_a = l % 5; // how many bytes in add-group? in: 0 . 2 3 4, out: 0 1 2 3
    if (last_a === 1) return false; // impossible source length for vc85
    let outlen = gcnt * 4 + (last_a ? (last_a - 1) : 0), // calculate result length
        out = new Uint32Array(gcnt + 1); // create temporary output array
    let oview = new DataView(out.buffer); // make wr-handler for this array

    // walk source array and convert vc85-chars to vc85-indexes if possible
    for (i=0; i<l; i++) {
        c = dview.getUint8(i);
        p = bc[c];
        if (!p) return false; // no index for this char - exit err
        dview.setUint8(i, p-1); // all indexes have +1
    }

  let s, k85 = [1, 85, 7225, 614125, 52200625];
    // decoding
    for (g = 0; g <= gcnt; g++) {
        wr = g * 4;
        rd = g * 5;
        if (g < gcnt) {
            s = 5;
        } else { // last group
            if (!last_a) break; // 5->4, 4->3, 3->2, 2->1
            s = last_a; // last_a may be 2,3,4 -> out 1 2 3
        }
        dec = 0;
        while(s) {
            dec += dview.getUint8(rd++) * k85[--s];
        }
        oview.setUint32(wr, dec);
    }
    let res_arr = new Uint8Array(outlen);
    // copy full groups
    for(i = 0; i < gcnt * 4; i++) {
        res_arr[i] = oview.getUint8(i);
    }
    // copy incomplete group (if have)
    for(i = i; i < outlen; i++) {
        res_arr[i] = oview.getUint8(i+5-last_a);
    }
    if (utf8_str_out) {
        res_arr = cn2conv.buff2str(res_arr.buffer);
    }
    return res_arr;
},

base6400_encode: function(data, uni_start = 13312) {
    data = this.base64_encode(data, false);
    let dec,i,l = data.length, chars = this.b64s + '+/=', b64n = new Uint8Array(255);
    for(i=0; i<65; i++) {
        b64n[chars.charCodeAt(i)] = i;
    }
    let str = '', dview = new DataView(cn2conv.str2buff(data,0));
    for(i=0; i<l; i+=2) {
        str += String.fromCharCode(uni_start + b64n[dview.getUint8(i+1)] * 64 + b64n[dview.getUint8(i)]);
    }
    return str;
},
base6400_decode: function(str, uni_start = 13312) {
    let dec, i, wr, l = str.length, chars = this.b64s + '+/==';
    let out = new Uint8Array(l * 2);
    for (i = 0; i < l; i++) {
        dec = (typeof str === 'string') ? str.charCodeAt(i) : str[i];
        dec -= uni_start;
        if (dec<0 || dec>4160) return false;
        wr = i*2;
        out[wr+1] = chars.charCodeAt(Math.floor(dec / 64));
        dec = (dec < 4096) ? (dec % 64) : (dec - 4096);
        out[wr] = chars.charCodeAt(dec);
    }
    out = cn2conv.buff2str(out.buffer,0);
    return this.base64_decode(out, false);
},

base64_decode: function(st, url_mode = false) {
    if (typeof st !== 'string') {
        if (Array.isArray(st)) {
            st = String.fromCharCode.apply(null, st);
        } else if (st instanceof ArrayBuffer) {
            st = cn2conv.buff2str(st, 0);
        }
    }
    try {
        st = atob(url_mode ? st.replace(/_/g, '/').replace(/-/g, '+') : st);
        if (typeof st === 'string') {
            st = cn2conv.str2buff(st,0);
        }
        return st;
    } catch (err) {
        return false;
    }
},

base64_encode: function(data, url_mode = false) {
    data = cn2conv.toUint8Array(data);
    let len = data.length,
        base64 = "",
        chars = this.b64s + (url_mode ? '-_' : '+/');

    for (i = 0; i < len; i += 3) {
        base64 += chars[data[i] >> 2];
        base64 += chars[((data[i] & 3) << 4) | (data[i + 1] >> 4)];
        base64 += chars[((data[i + 1] & 15) << 2) | (data[i + 2] >> 6)];
        base64 += chars[data[i + 2] & 63];
    }

    if ((len % 3) === 2) {
        base64 = base64.substring(0, base64.length - 1) + "=";
    } else if (len % 3 === 1) {
        base64 = base64.substring(0, base64.length - 2) + "==";
    }

    return base64;
},

hex_encode: function(in_data) {
    in_data = cn2conv.toUint8Array(in_data);
    return Array.from(in_data, b => ('0' + b.toString(16)).slice(-2)).join('');
},

hex_decode: function(str) {
    if (typeof str !== 'string') {
        str = cn2conv.buff2str(str);
    }
    let l = str.length,
        n, b,
        out = [];
    if (l % 2) return false;
    for (n = 0; n < l; n += 2) {
        b = parseInt(str.substr(n, 2), 16);
        if (isNaN(b)) return false;
        out.push(b);
    }
    out = new Uint8Array(out);
    return out.buffer;
},
utf8str_to_arr1251: function (str, only_cp = false) {
    let c, i, cnt = 0, out = [];
    for (i = 0; i < str.length; i++) {
        c = str.charCodeAt(i);
        if (c > 127) {
            if (c < 1025 || c > 1115) {
                return false; // out of cyrillic
            }
            if (c == 1025) { // Ё
                c = 168;
            } else if (c == 1105) { // ё
                c = 184;
            } else {
                c -= 848;
            }
            cnt++;
        }
        out.push(c);
    }
    if (only_cp && !cnt) return false;
    return new Uint8Array(out);
},

arr1251_to_utf8str: function (u8arr, cp='windows-1251') {
    let dc = new TextDecoder(cp);
    u8arr = cn2conv.toUint8Array(u8arr);
    return dc.decode(u8arr);
},

};
