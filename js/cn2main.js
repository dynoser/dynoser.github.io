"use sctrict";
/*
 * Circon2 allows you to encode data in multiple circular-containers.
 */
var circon2 = {
    dbg_show_key_hash: false,
    dbg_show_encrypt_hash: false,
    dbg_show_ea: false,

    // is cn2curv loaded?
    maxbasis: (function() {
        return (typeof cn2curv === 'undefined') ? 0 : cn2curv.maxbasis;
    })(),

    // ============ CIRCON2 Header ============
    // CIRCON2 header format: 16-bytes
    //  0
    // 00: 1 tbyte          216,217 = curves-mode, 218,219 = scarity-mode (last bit = 1=password required)
    // 01: 1 basis          How many containers required for restore data (exceptions: 0 means basis=parts, 1 special-scarcity-alg variants)
    // 02: 2 parts          How many parts created in this seria
    //  4
    // 04: 2 surplus        Parameter about encrypted-data-length % parts
    // 06: 1 curvlen        count of curves-alg-values (for curves-alg only)
    // 07: 1 mode_h         (encrypted) byte contains padding + data-mode parameters
    //  8
    // 08: 4 crc32h         (encrypted) CRC32 for source data (first 16K-bytes only)
    // 12
    // 12: 2 num            number of the current container (different for each container in seria)
    // 14  1 bp             bytes-per-each-curves-value or key-frag-len (may be different in seria)
    // 15: 1 extbyte        extra-byte in header, reserved for external algs, 0 by default

    /**
     * Pack CIRCON2-header from header-array to 16-bytes ArrayBuffer
     * 
     * @param array hd - array of header (all keys required)
     * @return ArrayBuffer
     */
    header16pack: function (hd) {
        // create 16-bytes ArrayBuffer for header
        let hbuff = new ArrayBuffer(16);
        let hview = new DataView(hbuff);
        this.header16write(hview, hd);
        return hbuff;
    },

    header16write: function (hview, hd) {
        // Write header-values to view-object
        hview.setUint8(0, hd.tbyte);   // tbyte
        hview.setUint8(1, hd.basis);   // basis
        hview.setUint16(2, hd.parts);  // parts
        hview.setUint16(4, hd.surplus);// surplus
        hview.setUint8(6, hd.curvlen); // curvlen
        hview.setUint8(7, hd.mode_h);  // mode_h
        hview.setUint32(8, hd.crc32h); // crc32h
        hview.setUint16(12, hd.num);   // num
        hview.setUint8(14, hd.bp);     // bp
        hview.setUint8(15, hd.extbyte);// extbyte
    },

    header16unpack: function (hbuff, quick_check = false) {
        let l = hbuff.byteLength;
        if (l < 16) {
            return "Too short data, no header";
        }
        var hview = new DataView(hbuff);
        let tbyte = hview.getUint8(0);    // 0
        if (tbyte < 216 || tbyte > 219) {
            return "No circon2 header";
        }

        let basis = hview.getUint8(1); // 1
        let parts = hview.getUint16(2); // 2 3
        let surplus = hview.getUint16(4); // 4 5
        let curvlen = hview.getUint8(6); // 6
        let mode_h = hview.getUint8(7); // 7

        let crc32h = hview.getUint32(8); // 8 9 10 11

        let num = hview.getUint16(12); // 12 13
        let bp = hview.getUint8(14); // 14
        let extbyte = hview.getUint8(15); // 15

        // calculate: curv, pass_req
        let curv = !(tbyte & 2);
        let pass_req = tbyte & 1;
        // calculate: serial
        let serial = new Uint8Array(hbuff.slice(0,12));
        serial = cn2tran.base64_encode(serial, true);
        let hd = {
            tbyte: tbyte,
            basis: basis,
            parts: parts,
            surplus: surplus,
            curvlen: curvlen,
            mode_h: mode_h,
            crc32h: crc32h,
            num: num,
            bp: bp,
            extbyte: extbyte,
            serial: serial,
            curv: curv,
            pass_req: pass_req
        };

        if (quick_check) {
            hd = this.header_quick_check(hd);
        }

        return hd;
    },

    header_quick_check: function(hd) {
        let basis = hd.basis;
        let parts = hd.parts;
        if (!basis) { // zero-basis exception
            basis = parts;
        }
        if (parts < basis) {
            return "parts is less than basis";
        }
        let num = hd.num;
        if (num > parts) {
            return "parts is less than num";
        }
        let alg = 0;
        let frags_cnt = false;
        let data_p = -16;
        let bp = hd.bp;
        let curvlen = hd.curvlen;
        let cont_data = true;
        if (hd.curv) { // curve alg: basis, parts, bp
            if (basis < 2) {
                return "Illegal basis for curves-alg";
            }
            // Q: have AES data?
            // A: if curvlen === 0 than NO, else YES
            if (curvlen) {
                // Where key-data end and AES-data begin?
                data_p = bp * curvlen;
            } else {
                cont_data = false;
            }
            if (bp != 1 && bp != 2 && bp != 4 && bp != 8) {
                return "Unsupported bp-range";
            }
        } else {
            if (parts <= hd.surplus) {
                return "surplus must be less than parts";
            }
            if (basis === 2) {
                frags_cnt = parts - 1;
                alg = -1;
            } else if (basis === parts) {
                frags_cnt = 1;
                alg = 1;
            } else if (basis === parts - 1) {
                alg = 2;
                frags_cnt = 2;
            } else {
                return "Illegal basis/parts for scarcity-alg";
            }
            // bp = key-frag-len (bytes)
            data_p = bp * frags_cnt;
        }
        hd.alg = alg; // alg for key
        hd.alg_d = alg ? alg : -1; // alg for data
        hd.frags_cnt = frags_cnt;
        hd.data_p = data_p;
        hd.cont_data = cont_data;
        return hd;
    },

    /**
     * Calc recommend alg:
     * 
     * Return:
     * -1 = scarcity (all without one fragment in each container)
     *  0 = curves for key (-1 for other data)
     *  1 = scarcity (one fragment per container)
     *  2 = scarcity (two fragments per container)
     */
    alg_reco: function (basis, parts, key_fragment_len) {
        alg = 0;
        if (key_fragment_len) {
            if (basis === 2 && (parts < 8 || parts > this.maxbasis)) {
                alg = -1;
            } else if (!basis || basis === parts) {
                alg = 1;
            } else if (basis === parts - 1) {
                alg = 2;
            }
        }
        return alg;
    },

    req_verbose: function(hd, lang=false) {
        let basis = hd.basis;
        if (false === lang) {
            lang = {
                mul2:'а',
                mul5:'ов',
                req:'Требуется',
                con:'контейнер',
                andpass:'и пароль',
                decrypt:'расшифровки',
                recover:'восстановления',
                todo:'для',
                thecont:'содержимого',
                totalcre:'Всего было создано',
                werecre:'серии',
            },
            lang = {
                mul2:'s',
                mul5:'s',
                req:'You need',
                con:'container',
                andpass:'and password',
                decrypt:'decrypt',
                recover:'recover',
                todo:'to',
                thecont:'the content',
                totalcre:'In total',
                werecre:'were created in seria',
            };
        }
        let st = lang.req + ' <b>' + basis + '</b> ' + lang.con;
        if (basis > 1) {
            st += (basis < 5) ? lang.mul2 : lang.mul5;
        }
        if (hd.pass_req) {
            st += ' <font color="maroon"><b>' + lang.andpass + '</b></font>';
        }
        st += ' ' + lang.todo + ' ' + ((hd.basis>1 || hd.pass_req) ? lang.decrypt : lang.recover) + ' ' + lang.thecont;
        let parts = hd.parts;
        if (parts > 1) {
            st += "\n" + lang.totalcre + ' ' + parts + ' ' + lang.con + ((parts < 5) ? lang.mul2 : lang.mul5) + ' ' + lang.werecre + ' ' +hd.serial;
        }
        return st;
    },

    header_verbose: function(hd) {
        let tr_modes = ['binary','utf8','ascii-127','cp1251','base64','base64url','hex', 'vc85', 'base6400'];
        let skip_keys = {tbyte:1,num:1,curv:1,data_p:1,cont_data:0,frags_cnt:1,crc32h:0,crc32d:0,mode_h:0,surplus:0,bp:0};
        let verb = [];
        for(let [k,v] of Object.entries(hd)) {
            if (typeof skip_keys[k] !== 'undefined') {
                let s = skip_keys[k];
                if (2 !== s) {
                    if (s) {
                        continue;
                    }
                    if (hd.crc32ok) {
                        continue;
                    }
                }
            }
            if (k === 'pass_req') {
                k = 'password';
                v = v ? 'Required' : 'No additional password';
            }
            if (k === 'basis') {
                if (!v) v = hd.parts;
                v += ' containers require to decode';
            }
            if (k === 'parts') {
                v +=  (v > 1) ? ' containers in seria' : ' encrypted container AES-256-CBC';
            }
            if (k === 'alg') {
                k = 'alg_keys';
                if (hd.cont_data) {
                    v = (v) ? 'scarcity(' + v + ' fragments per each container)' : 'curves';
                } else {
                    v = "No AES key, curves-mode";
                }
            }
            if (k === 'alg_d') {
                k = 'alg_data';
                if (hd.cont_data) {
                    v = 'scarcity(' + v + ' fragments per each container)';
                } else {
                    v = 'curves-encoded-data';
                }
            }
            if (k === 'trans_code') {
                k = 'transport_encode';
                v = tr_modes[v] + " (code=" + v + ')';
            }
            if (k === 'mode_d') {
                k = 'inside_data_encode';
                v = tr_modes[v] + " (code=" + v + ')';
            }

            if (k === 'curvlen') {
                k = 'key_length';
                if (hd.curv) {
                    if (v) {
                        v = (v * 8) + " bits (curves-encoded-key)";
                    } else {
                        v = "No AES key, curves-encode";
                    }
                } else {
                    v = (hd.bp * 8) + " bits (scarcity-encoded-key)";
                }
            }
            if (k === 'bp') {
                v = v ? ((v * 8) + " bits") : 'Curvers only (without AES)';
                if (!hd.basis) v='Key 256 bits (sha256 from Password)';
            }
            if (k === 'curv') {
                k = 'alg_head';
                v = v ? 'curves' : 'scarcity';
                if (!hd.basis) v='AES-256-CBC';
            }
            verb[k]=v;
        }
        return verb;
    },

    /**
     * In:
     *  transport_detect_mode 
     *   = 0 : the source contains binary-data
     *   = 1 : use only the first 60 bytes to detect transport-encoding
     *   = 2 : if header detected successful, try to unpack all data from source string
     * 
     * @param {string} str 
     * @param {integer} full_decode 
     */
    headerDetect: function(str, transport_detect_mode=1) {
        let trans_code = 0;
        let dt, buff = str;
        // if transport auto-detect requested (not binary)
        if (transport_detect_mode) {
            dt = cn2tran.transportDetectQuick(str, true);
            if (false === dt) {
                return "Transport encoding unrecognized";
            }
            // get transport-encoding code
            trans_code = dt[0];
            // get short data (from first 60 bytes)
            buff = dt[1];
        }
        let hd = this.header16unpack(buff, true);
        if (typeof hd === 'string') {
            return hd;
        }

        // only for non-binary modes
        if (transport_detect_mode) {
            // if full-decode requested
            if (transport_detect_mode > 1) {
                // try to unpack with current trans_conde
                buff = cn2tran.decode_by_data_mode(trans_code, str);
                if (false === buff) {
                    // try to transport-detect again, with full-decode string
                    dt = cn2tran.transportDetect(str);
                    // if successful detected
                    if (dt[0] === trans_code) {
                        buff = dt[1];
                    // if special case: 4-base64-classic + 5-base64-url = 9
                    } else if ((dt[0] + trans_code) === 9) {
                        trans_code = 5;
                        buff = dt[1];
                    // two differen encodes detected
                    } else {
                        // new code will be considered more correct
                        trans_code = dt[0];
                        // recursive self-call without transport-auto-detect
                        hd = this.headerDetect(dt[1], 0);
                        if (typeof hd === 'string') {
                            return hd;
                        }
                    }
                } else if (typeof buff === 'string') {
                    buff = cn2conv.str2buff(buff, 0);
                }
            }
            hd.buff = buff;
        }

        hd.trans_code = trans_code;

        return hd;
    },

    // === decode / encode ===
    encode: async function(basis, parts, data_buff, secure_key_len = 8, pass = '', out_encode = 4) {
        // if out_encode not set - use base64url by default
        out_encode = (typeof out_encode === 'undefined') ? 1 : out_encode;
        let pass_is_empty = (pass.length === 0);
        let alg = this.alg_reco(basis, parts, secure_key_len);
        let key_data_src = false;
        let mode_d = 0;
        if (!alg) {
            if (!secure_key_len) {
                if (!data_buff.length) {
                    return "No source data";
                }
                data_buff = this.data_prep(data_buff, 0);
                mode_d = data_buff.mode_d;
                key_data_src = data_buff.data_u8.buffer;
            }
        }
        let hk = this.headers_keys_encode(basis, parts, secure_key_len, alg, key_data_src, pass_is_empty);
        if (typeof hk === 'string') {
            return hk;
        }
        hk = await this.append_aes(data_buff, hk, pass, mode_d);
        if (typeof hk === 'string') {
            return hk;
        }
        for(let [k, el] of Object.entries(hk)) {
            if (typeof el.byteLength === 'number') {
                hk[k] = cn2tran.encode_by_data_mode(out_encode, el);
            }
        }
        return hk;
    },

    decode: async function(in_data, pass='', transport_detect=true) {
        let dt = this.combine(in_data, pass, transport_detect);
        if (typeof dt === 'string') {
            return {
                err: dt,
                errs: [],
            };
        }
        if (typeof dt.err === 'string') {
            return dt;
        }
        // crc32z data_aes hd key_data aes_data pass
        let key_data = dt.key_data;
        let hd = dt.hd;
        let errs = (typeof dt.errs !== 'undefined') ? dt.errs : [];
        if (hd.cont_data) {
            dt = await this.aes_unprep(dt.aes_data, hd.crc32h, hd.mode_h, key_data, dt.pass);
        } else {
            dt = this.data_unprep(key_data, dt.crc32z, hd.crc32h, hd.mode_h, false);
        }
        if (typeof dt === 'string') {
            return dt;
        }
        dt.hd = hd;
        dt.errs = errs;
        return dt;
    },

    combine: function(in_data, pass='', transport_detect=true) {

        // check input, divide by elements
        let arr = cn2conv.toNumKeyArr(in_data);
        if (!Array.isArray(arr)) {
            return "Bad source data";
        }

        // count of input elements
   //    if (arr.reduce(elcnt => ++elcnt, 0) < 1) {
   //         return "No source data";
   //     }

        let bin_arr = [];
        let errs = []; // errors list

        // full-detect=2 or binary=0
        transport_detect = transport_detect ? 2 : 0;

        let hd, serial, sb;

        // walking by array
        arr.every((st, k) => {
            if (typeof st === 'string') {
                if (st.substr(8,1) === ":") {
                    pass = st.substr(9).trim();
                    return true;
                }
                sb = 'SKIP: ' + st.substr(0,16) + ((st.length > 16) ? '... : ' : ': ');
            } else {
                sb = 'SKIP: (' + (typeof st) + '):';
            }
            let ht = this.headerDetect(st, transport_detect);
            if (typeof ht === 'string') {
                errs.push(sb + ht);
                return true; // skip this element
            }
            if (typeof ht.trans_code !== 'number') {
                errs.push(sb + "Can't decode damaged");
                return true;
            }

            // check serial id
            if (typeof serial === 'undefined') {
                hd = ht;
                serial = hd.serial;
                //if (hd.parts === 1) {
                    // AES container
                    //return false;
                //}
            } else if (serial !== ht.serial) {
                errs.push(sb + "Different serial: " + ht.serial + ' != ' + serial);
                return true;
            }
            if (!transport_detect) {
                ht.buff = st;
            }

            bin_arr.push(ht)
            return true;
        });

        // try to decode keys
        let dk = this.headers_keys_decode(bin_arr);

        if (typeof dk === 'string') {
            return {
                err: dk,
                errs: errs,
            };
        }
        if (typeof dk.err === 'string') {
            dk.errs = errs;
            return dk; //err , hd
        }

        let aes_data = false;
        if (hd.cont_data) {
            // try to invoke aes data
            aes_data = cn2scar.scarcity_sum(dk.data_arr, hd.parts, hd.surplus, hd.alg_d);
            if (typeof aes_data === 'string') {
                return {
                    err: aes_data,
                    errs: errs,
                    hd: hd
                };
            }
        }
        delete hd.buff;
        return {
            aes_data: aes_data,
            key_data: dk.key_data,
            pass: pass,
            hd: hd,
            crc32z: dk.crc32z,
            errs: errs,
        };
    },

    // === headers with keys ====

    /**
     * Accepted only: UInt8Arrays or ArrayBuffer types, other ignore
     * 
     * @param {Array} in_bin_arr 
     */
    headers_keys_decode: function(in_bin_arr) {
        // check input, divide by elements
        var arr = cn2conv.toNumKeyArr(in_bin_arr);
        if (!Array.isArray(arr)) {
            return "Bad source data";
        }
        let elcnt = 0;
        let keys_arr = [];
        let data_arr = {};
        let errs = [];
        let serial;
        let hd,ht;
        // walking by array
        for (let [k, container] of Object.entries(arr)) {

            if (typeof container.buff !== 'undefined') {
                ht = container;
                container = ht.buff;
            } else {
                if (typeof container.buffer === 'object') {
                    container = container.buffer;
                }
                ht = this.header16unpack(container, true);
            }

            if (typeof container === 'string') {
                errs.push("SKIP: Source data must have binary-type, not string");
                continue;
            }

            if (typeof ht === 'object' && typeof keys_arr[ht.num] === 'undefined') {
                if (typeof serial === 'undefined') {
                    serial = ht.serial;
                }
                if (serial === ht.serial) {
                    hd = ht;
                    let bp = ht.bp;
                    let data_p = 16 + hd.data_p;
                    if (!data_p) {
                        data_p = container.byteLength;
                        data_p -= (data_p % bp); 
                    }
                    let key_var = container.slice(16, data_p);
                    if (typeof data_arr[hd.num] !== 'undefined') {
                        errs.push("Container with number #" + hd.num + " already exist");
                    }
                    data_arr[hd.num] = container.slice(data_p);
                    data_p -= 16;
                    if (hd.curv) {
                        let dview = new DataView(key_var);
                        let rd = 0, tmp_arr = [];
                        switch (bp) {
                            case 2:
                                while (rd < data_p) {
                                    tmp_arr.push(BigInt(dview.getUint16(rd)));
                                    rd += bp;
                                }
                                break;
                            case 4:
                                while (rd < data_p) {
                                    tmp_arr.push(BigInt(dview.getUint32(rd)));
                                    rd += bp;
                                }
                                break;
                            case 8:
                                while (rd < data_p) {
                                    tmp_arr.push(dview.getBigUint64(rd));
                                    rd += bp;
                                }
                                break;
                            case 1:
                                while (rd < data_p) {
                                    tmp_arr.push(BigInt(dview.getUint8(rd)));
                                    rd += bp;
                                }
                        }
                        key_var = tmp_arr;
                    }
                    keys_arr[hd.num] = key_var;
                    elcnt++;
                } else {
                    errs.push()
                }
            }
        }
        if (typeof hd === 'undefined') {
            return {
                err: "No source data found",
                errs: errs
            }
        }

        // how many parts required?
        let min_parts = 2;
        if (hd.alg > 0) {
            min_parts = hd.parts - hd.alg + 1;
        }
        if (elcnt < min_parts) {
            return {
                err: "Lack parts to restore data",
                hd: hd,
                errs: errs
            };
        }
        let key_data, crc32z =  false;
        if (hd.curv) {
            key_data = cn2curv.curves_decode(keys_arr);
            if (false !== key_data) {
                crc32z = key_data.crc32z;
                key_data = key_data.data;
            }
        } else {
            key_data = cn2scar.scarcity_sum(keys_arr, hd.parts, 0, hd.alg);
        }

        return {
            hd: hd,
            key_data: key_data,
            crc32z: crc32z,
            data_arr: data_arr,
        };
    },

    back_key_check: true, // parameter for function below: check encoded key by decode back

    headers_keys_encode: function(basis, parts, secure_key_len=8, alg=false, key_data=false, pass_is_empty=true) {
        if (!basis) { // zero-basis exception
            basis = parts;
        }

        // check $parts and $basis
        if (typeof parts !== 'number' || typeof basis !== 'number' || parts < basis || parts < 1 || basis < 1) {
            return `Error: illegal parameters basis=${basis}/parts=${parts}`;
        }

        //auto-detect alg (if need)
        if (alg === false) {
            alg = this.alg_reco(basis, parts, secure_key_len);
        }

        // check the ability of the selected alg
        if (alg < 0) { // alg = -1
            // check for scarcity-mode
            if (basis !== 2) {
                return `Error: can't use scarcity-alg for basis=${basis} with parts=${parts}`;
            }
        } else if (!alg) { // alg = 0
            // check for curves-mode
            if ((basis < 2) || basis >= this.maxbasis) {
                if (!this.maxbasis) {
                    basis += " (curves-module not inicialized)";
                }
                return `Error: can't use curves-alg for basis=${basis}`;
            }
        } else if (alg === 1) { // alg = 1
            // check alg-1
            if (basis !== parts) {
                return `Error: can't use +1 alg because basis: ${basis} <> parts:${parts}`;
            }
        } else if (alg === 2) { // alg = 2
            if (basis !== parts - 1) {
                return `Error: can't use +2 alg because basis: ${basis}+1 <> parts:${parts}`;
            }
        } else {
            return "Unknown alg (supported: -1, 0, 1, 2)";
        }

        // how many fragments in each part?
        let data_frags_in_part = (alg < 1) ? (parts - 1) : alg;

        let tbyte = pass_is_empty ? 0 : 1;

        let keys_arr;

        let crckey = false;
        let cont_data = true;
        let hd = {
            tbyte: tbyte,
            basis: basis,
            parts: parts,
            surplus: 0,
            curvlen: 0,
            mode_h: 0,
            crc32h: 0,
            extbyte: 0
        };
        // create keys
        if (!alg) { // create keys for curves-mode
            tbyte += 216;
            hd.tbyte = tbyte;
            if (false !== key_data) {
                // convert to Uint8Arr (if need)
                if ((key_data instanceof ArrayBuffer) || (typeof key_data.byteLength === 'undefined')) {
                    key_data = cn2conv.toUint8Array(key_data);
                }
            }
            if (secure_key_len) {
                if (false !== key_data) {
                    if (key_data.byteLength !== secure_key_len) {
                        return "Length of data_for_keys not equal with secure_key_len";
                    }
                } else {
                    key_data = this.random_bytes(secure_key_len);
                }
            } else {
                cont_data = false;
            }
            if (typeof key_data.buffer === 'undefined')  {
                return "Bad type of source data";
            }
            keys_arr = cn2curv.curves_encode(basis, parts + 1, key_data.buffer);

            // check decode-back (if need)
            if (this.back_key_check) {
                let back = cn2curv.curves_decode(keys_arr);
                if (keys_arr[0] != back.crc32z) {
                    return "Can't decode back in this implementation curves-alg";
                }

                let max_y, bp, sk, elc, yarr, out_arr, dview, i, v, p;
                for(i=0; i<back.data.length; i++) {
                    if (back.data[i] != key_data[i]) {
                        return "Can't back-decode in this implementation curves-alg";
                    }
                }
            }

            hd.curvlen = secure_key_len;

            // re-pack keys_arr to [bp, key]
            for(num = 1; num  <= parts; num++) {
                // calculate bit range for each elements
                yarr = keys_arr[num];
                elc = yarr.length;
                // calculate how many bytes need to encode each elements of yarr
                max_y = yarr.reduce((max, y) => (y > max) ? y : max, BigInt(0));
                bp = 2 ** cn2curv.FMT.findIndex(v => v > max_y);
                // how many elements need to skip for header and for create elements
                sk = 16 / bp;
                switch (bp) {
                    case 0.5:
                        return "Out of range";
                    case 8: //8 bytes
                        out_arr = new BigInt64Array(sk + elc);
                        break;
                    case 4: //4 bytes
                        out_arr = new Uint32Array(sk + elc);
                        break;
                    case 2: //2 bytes
                        out_arr = new Uint16Array(sk + elc);
                        break;
                    case 1: // 1 byte (impossible)
                        out_arr = new Uint8Array(sk + elc);
                }
                // move all elements from yarr to out_arr
                dview = new DataView(out_arr.buffer);
                hd.num = num;
                hd.bp = bp;
                this.header16write(dview, hd);
                for(i=0; i<elc; i++) {
                    v = yarr[i];
                    p = (i + sk) * bp;
                    if (bp == 1) {
                        dview.setUint8(p, Number(v));
                    } else if (bp == 2) {
                        dview.setUint16(p, Number(v));
                    } else if (bp == 4) {
                        dview.setUint32(p, Number(v));
                    } else {
                        dview.setBigUint64(p, v);
                    }
                }
                keys_arr[num] =new Uint8Array(out_arr.buffer);
            }
            crckey = keys_arr[0];
        } else { // create keys ($parts, $data_for_divide, $alg, $base_part_len)
            tbyte += 218;
            hd.tbyte = tbyte;
            hd.bp = secure_key_len;
            if (false !== key_data) {
                if (key_data.length != parts * secure_key_len) {
                    return "Bad key_data length (expected: " + (parts * secure_key_len) + ')';
                }
            }
            keys_arr = cn2scar.scarcity_div(parts, key_data, alg, secure_key_len);
            key_data = keys_arr[0];

            if (this.back_key_check) {
                let back = cn2scar.scarcity_sum(keys_arr, parts, 0, alg);
                let bad = true;
                if (typeof back.byteLength === 'number') {
                    bad = false;
                    for(i=0; i<back.byteLength; i++) {
                        if (back[i] !== key_data[i]) {
                            eq = true;
                            break;
                        }
                    }
                }
                if (bad) {
                    return "Code error: back-sum-key";
                }
            }
            // append headers
            for(num = 1; num <= parts; num++) {
                let l = keys_arr[num].byteLength;
                let out_arr = new ArrayBuffer(16 + l);
                hd.num = num;
                this.header16write(new DataView(out_arr), hd);
                out_arr = new Uint8Array(out_arr);
                for (i=0; i<l; i++) {
                    out_arr[i+16] = keys_arr[num][i];
                }
                keys_arr[num] = out_arr;
            }

        }
        keys_arr[0] = {
            alg: alg,
            basis: basis,
            parts: parts,
            data_frags_in_part: data_frags_in_part,
            key_data: key_data,
            crckey: crckey,
            tbyte: tbyte,
            cont_data: cont_data
        };
        return keys_arr;
    },

    // ==== Data Append ====

    invoke_aes: function(in_bin_arr) {
        let de = this.headers_keys_decode(in_bin_arr);
        if (typeof de === 'string') {
            return de;
        }
        let hd = de.hd;
        if (!hd.cont_data) {
            return "No AES data";
        }
        return cn2scar.scarcity_sum(de.data_arr, hd.parts, hd.surplus, hd.alg);
    },

    append_aes: async function(data_in, head_key_arr, pass='', mode_d=0, meta_data=false) {
        if (typeof head_key_arr[0].key_data === 'undefined') {
            return "Illegal head_key_arr";
        }
        let zer = head_key_arr[0];

        let key_data = zer.key_data;
        let parts = zer.parts;
        let alg =  zer.alg;
        let enc = false;
        let enc_data = new ArrayBuffer(0);
        if (zer.cont_data) {
            enc = await this.aes_prep(data_in, key_data, pass, mode_d, meta_data);
            if (typeof enc === 'string') {
                return enc; // error
            }
            if (typeof enc.encrypted_data !== 'undefined') {
                enc_data =  enc.encrypted_data;
            }
        } else {
            enc = this.data_prep(data_in.data_u8, zer.crckey, data_in.mode_d, data_in.lent);
        }
        let mode_h = enc.mode_h;
        let crc32h = enc.crc32h;

        let dlen = enc_data.byteLength;
        let surplus = dlen % parts;

        let data_div;
        if (zer.cont_data) {
            data_div = cn2scar.scarcity_div(parts, enc_data, alg, 0);
            if (data_div.length !== head_key_arr.length) {
                return "Code error";
            }
        }
        let hview;
        for(num=1; num<= parts; num++) {
            //modify header
            hview = new DataView(head_key_arr[num].buffer);
            hview.setUint16(4, surplus);// surplus
            hview.setUint8(7, mode_h);  // mode_h
            hview.setUint32(8, crc32h); // crc32h
            if (zer.cont_data) {
                head_key_arr[num] = new Uint8Array([...head_key_arr[num], ...data_div[num]]);
            }
        }

        return head_key_arr;
    },

    aes_prep: async function(data_in, key_data, pass='', mode_d=0, meta_data=false) {
        if (false !== meta_data) {
            if (mode_d && (mode_d != 10)) {
                return 'data with meta_data must have mode_d=10';
            }
            mode_d = 10;
            meta_data = cn2conv.toUint8Array(meta_data);
            if (!(meta_data.buffer instanceof ArrayBuffer) || meta_data.byteLength > 65535) {
                return "Illegal meta_data format";
            }
        }
        let sumkey = await this.sum_secret_key(key_data, pass);
        
        let dp = this.data_prep(data_in, sumkey.crckey, mode_d);

        if (typeof dp === 'string') {
            return dp; // error
        }

        key_data = cn2conv.in2buff(key_data);

        let encrypted_data = await this.aes256(dp.data_u8, sumkey, false, true);
        if (typeof encrypted_data === 'string') {
            return encrypted_data;
        }
        return {
            encrypted_data: encrypted_data.data,
            crckey: encrypted_data.crckey,
            crc32h: dp.crc32h,
            mode_h: dp.mode_h
        };
    },

    aes_unprep: async function(data_in, crc32h, mode_h, key_data, pass='') {
        let sumkey = await this.sum_secret_key(key_data, pass);
        let decrypted_data = await this.aes256(data_in, sumkey, false, false);
        let data = this.data_unprep(decrypted_data.data, sumkey.crckey, crc32h, mode_h, false);
        return data;
    },

    /**
     * Prepare data to encrypt
     * 
     * @param {ArrayBuffer|String} data_in 
     */
    data_prep: function(data_in, crckey, mode_d=0, lent=false) {

        // check source data
        if (!(data_in instanceof ArrayBuffer)) {
            if (typeof data_in === 'string') {
                data_in = cn2tran.data_mode_detect(data_in);
                if (false === data_in) {
                    return "No source data";
                }
                mode_d = data_in[0];
                data_in = data_in[1];
            } else if (typeof data_in.buffer === 'object') {
                data_in = data_in.buffer;
            } else {
                return "Unrecognized source data";
            }
        }

        // calculate ea, lent, and padd
        let dt = this.ea_make(data_in);
        if (false === lent) {
            lent = dt.lent;
        }

        // append padd to end of data_buff (if need)
        let padd = dt.padd;
        if (padd.byteLength) {
            data_in = new Uint8Array(data_in);
            data_in = [...data_in, ...padd];
        }
        data_in = new Uint8Array(data_in);

        // calculate CRC32 of source data (with random bytes if added)
        let crc32d = this.crc32(data_in, true);

        // encrypt crc32d to crc32h
        let crc32h = this.calc_crc32h(dt.ea, crc32d, crckey);

        // encrypt mode_d and lent to mode_h
        let mode_h = this.pack_mode_h(dt.ea, crckey, lent, mode_d);

        return {
            crc32d: crc32d,
            crc32h: crc32h,
            mode_d: mode_d,
            mode_h: mode_h,
            data_u8: data_in,
            lent: dt.lent
        };
    },

    data_unprep: function(data_buff, crckey, crc32h, mode_h, break_if_bad_crc = true) {
        if (!(data_buff instanceof ArrayBuffer) && (typeof data_buff === 'object')) {
            data_buff = data_buff.buffer;
        }
        if (!(data_buff instanceof ArrayBuffer) || data_buff.byteLength < 12) {
            return "Bad source data format";
        }

        // calculate crc32d (by data with padding)
        let crc32d = this.crc32(data_buff, true);

        // calculate ea
        let dt = this.ea_make(data_buff);

        // calculate crc32x for compare with crc32h
        let crc32x = this.calc_crc32h(dt.ea, crc32d, crckey);

        if (crc32x !== crc32h) {
            // BAD CRC
            if (break_if_bad_crc) {
                return {
                    crc32ok: false,
                    crc32d: crc32d,
                    mode_d: 0,
                    data: data_buff,
                };
            }
        }

        // decode mode_d and lent
        let mode_d = this.unpack_mode_h(dt.ea, crckey, mode_h);
        let lent = mode_d.lent;
        mode_d = mode_d.mode_d;

        let l16 = data_buff.byteLength % 16;
        l16 = l16 - lent;
        if (l16) {
            // need to reduce
            if (l16 < 0) l16 += 16;
            data_buff = data_buff.slice(0, -l16);
        }

        // convert data_buff to Uint8Array or string by mode_d
        data_buff = cn2tran.encode_by_data_mode(mode_d, data_buff);

        return {
            crc32ok: (crc32x == crc32h),
            crc32d: crc32d,
            mode_d: mode_d,
            data: data_buff
        };
    },


    /**
     * Adding random-padding to end of last-data-frame
     * 
     * Returns:
     *  -string error description, or
     *  -array with these keys:
     *  [ea] - array of 3 x Uint32 ea[1], ea[2], ea[3] for extended encryption
     *  [lent] - length of tail16 before padding
     *  [padd] - random bytes, added to tail16 (0-12 bytes) Uint8Array
     *  [tail16] - result ArrayBuffer, from 12 to 15 bytes
     *
     * @param {ArrayBuffer} data_buff - source data
     * @return {array|string}
     */
    ea_make: function(data_buff) {
        if (!(data_buff instanceof ArrayBuffer))  {
            return "ArrayBuffer required";
        }
        let data_len = data_buff.byteLength;
        let lent = data_len % 16;
        let tail16 = data_buff.slice(lent ? -lent : data_len);
        let padd = new Uint8Array(0);
        if (lent < 12) {
            tail16 = new Uint8Array(tail16);
            padd = this.random_bytes(12 - lent);
            let summar = new Uint8Array(12);
            let i = -1, r = 0;
            while (++i < tail16.byteLength) {
                summar[i] = tail16[i];
            }
            while (i < summar.byteLength) {
                summar[i++] = padd[r++];
            }
            tail16 = summar.buffer;
        }
        let dview = new DataView(tail16);
        let ea = [
            0,
            dview.getUint32(0),
            dview.getUint32(4),
            dview.getUint32(8)
        ];
        if (this.dbg_show_ea) {
            let sh = {e1:ea[1],e2:ea[2],e3:ea[3],lent:lent,dl:data_len,t16:tail16};
            console.log(sh);
        }

        return {
            ea: ea,
            lent: lent,
            padd: padd,
            tail16: tail16
        };
    },
    
    /**
     * Remove padding from last-frame of data_buff to lent length
     * 
     * Return:
     *  - string error description
     *  - array with keys:
     *  [ea] - array of 3 x UInt32: ea[1], ea[2], ea[3]
     *  [pdel] - hom many bytes removed from tail16
     *  [tail16] - ArrayBuffer of last-frame after padding removed
     *  [data_buff] - ArrayBuffer of data after padding removed
     * 
     * @param {ArrayBuffer} data_buff
     * @param {Number} lent
     * @return {Array|String}
     */
    padding_remove: function(data_buff, lent)
    {
        if (!(data_buff instanceof ArrayBuffer))  {
            return "ArrayBuffer required";
        }
        if (typeof lent !== 'number' || lent < 0 || lent > 15) {
            return "lent out of expected range";
        }
        let data_len = data_buff.byteLength;
        let l16 = data_len % 16;
        if (l16 < 12 || l16 > 15) {
            return "Length of tail16 out of expected range";
        }
        let tail16 = data_buff.slice(-l16);
        let dview = new DataView(tail16);
        let ea = [
            0,
            dview.getUint32(0),
            dview.getUint32(4),
            dview.getUint32(8)
        ];
        let pdel = 0;
        while (l16 && (l16 % 16 != lent)) {
            pdel++;
            l16--;
        }

        if (pdel) {
            data_buff = data_buff.slice(0, -pdel);
            tail16 = tail16.slice(0, -pdel);
        }

        return {
            ea: ea,
            pdel: pdel,
            tail16: tail16,
            data_buff: data_buff
        };
    },

    /**
     * Encode values mode_d and lent into one byte mode_h (XOR by ea and crckey)
     * 
     * @param {Array} ea 
     * @param {Uin32} crckey 
     * @param {Uint8} lent - 0..15
     * @param {Uint8} mode_d - 0..15
     */
    pack_mode_h: function(ea, crckey, lent, mode_d) {
        // put lent to 4 hight-bits, mode_d to 4 lower-bits
        let mode_x = (mode_d & 15) + ((lent % 16) << 4); // make high 4-bits
        let dview = new DataView(new ArrayBuffer(4));
        dview.setUint32(0, crckey);
        let c = [
            0,
            dview.getUint8(0),
            dview.getUint8(1),
            dview.getUint8(2),
            dview.getUint8(3),
        ];
        return 255 & (mode_x ^ ea[3] ^ ea[2] ^ ea[1] ^ c[1] ^ c[2] ^ c[3] ^ c[4]);
    },

    /**
     * Unpack lent and mode_d from mode_h (XOR by ea and crckey)
     * 
     * @param {Array} ea 
     * @param {Uint32} crckey 
     * @param {Uint8} mode_h 
     */
    unpack_mode_h: function(ea, crckey, mode_h) {
        let dview = new DataView(new ArrayBuffer(4));
        dview.setUint32(0, crckey);
        let c = [
            0,
            dview.getUint8(0),
            dview.getUint8(1),
            dview.getUint8(2),
            dview.getUint8(3),
        ];
        let mode_x = 255 & (mode_h ^ ea[3] ^ ea[2] ^ ea[1] ^ c[1] ^ c[2] ^ c[3] ^ c[4]);
        let lent = (mode_x & 240) >> 4;
        let mode_d = mode_x & 15;
        return {
            lent: lent,
            mode_d: mode_d,
        };
    },

    /**
     * Sum crc32d + ea + crckey to Uint32
     * 
     * @param {Array} ea - Array of 3 x Uint32
     * @param {Uint32} crc32d - crc32(first max.16Kbytes of source data)
     * @param {Uint32} crckey - crc32(secure-key)
     */
    calc_crc32h: function (ea, crc32d, crckey) {
        return cn2conv.toUint32(crc32d + ea[3] + ea[2] + ea[1] + crckey);
    },

 
    // ===== Crypto-primitives =====

    random_bytes: function(bytes_cnt) {
        return window.crypto.getRandomValues(new Uint8Array(bytes_cnt));
    },

    sha256: async function(in_data) {
        if (typeof in_data.buffer === 'undefined') {
            in_data = cn2conv.toUint8Array(in_data);
        }
        return await this.sha256u8(in_data);
    },

    sha256u8: async function(u8arr) {
        if (typeof sha256 === 'function') {
            let res = sha256.arrayBuffer(u8arr);
            return res;
        }
        return await crypto.subtle.digest({ name: 'SHA-256' }, u8arr.buffer);
    },

    sum_secret_key: async function(key_data, pass) {
        pass = cn2conv.toUint8Array(pass);
        if (pass.byteLength) {
            let rd, wr, newkey = new Uint8Array(key_data.byteLength + pass.byteLength);
            for(wr=0; wr<key_data.byteLength; wr++) {
                newkey[wr] = key_data[wr];
            }
            for(rd=0; rd<pass.byteLength; rd++) {
                newkey[wr++] = pass[rd];
            }
            key_data = newkey;
        }
        let crckey = this.crc32(key_data);

        // take sha-256 hash from keyu8
        let secret_key = await this.sha256(key_data);
        // take last 16 bytes from hash to vector
        let secret_u8 = new Uint8Array(secret_key);
        let vector = secret_u8.slice(16);
        if (this.dbg_show_key_hash) {
            console.log("keyHash: " + cn2tran.hex_encode(secret_u8));
        }

        return {
            secret_key: secret_u8,
            vector: vector,
            crckey: crckey,
        };
    },

    /**
     * Encrypt or Decrypt AES-256-CBC
     * 
     * if the source parameters are in string format, it must be utf-8
     * 
     * return:
     *  - string decription - if err
     *  - {data, keycrc} - if ok
     * 
     * @param {ArrayBuffer|Uint8Array|string} in_data - source data for encrypt or decrypt
     * @param {ArrayBuffer|Uint8Array|string|Object} key_data - source for create secret-key by sha256
     * @param {ArrayBuffer|Uint8Array|string|false} pass - additional data for key_data (just added to end of key_data)
     * @param {boolean} true_for_encrypt - true for encryption, false for decryption
     */
    aes256: async function(in_data, key_data, pass, true_for_encrypt) {
        in_data = cn2conv.toUint8Array(in_data);

        let sum_key = key_data;
        if (typeof sum_key.vector === 'undefined') {
            sum_key = await this.sum_secret_key(key_data, pass);
        } else {
            if (false !== pass) {
                return "Illegal key_data";
            }
        }
        if (typeof sum_key.vector === 'undefined' || typeof sum_key.secret_key === 'undefined') {
            return "Illegal key_data";
        }
        let vector = sum_key.vector;
        let secret_u8 = sum_key.secret_key;
        let crckey = sum_key.crckey;

        let out_data;

        if (this.dbg_show_encrypt_hash) {
            console.log((true_for_encrypt ? 'dec' : 'enc') + "Hash:" + sha256.hex(in_data));
        }

        // try aesjs
        if (typeof aesjs !== 'undefined') {
            try {
                let aesCbc = new aesjs.ModeOfOperation.cbc(secret_u8, vector);
                if (true_for_encrypt) {
                    out_data = aesjs.padding.pkcs7.pad(in_data);
                    out_data = aesCbc.encrypt(out_data);
                } else {
                    out_data = aesCbc.decrypt(in_data);
                    out_data = aesjs.padding.pkcs7.strip(out_data);

                }
            } catch(err) {
                console.log(err);
            }
        }

        // try browser crypto.subtle
        if (typeof out_data === 'undefined') {
            try {
                // convert secret_key from array to CryptoKey object
                let key_obj = await crypto.subtle.importKey('raw', secret_u8, { name: 'AES-CBC' }, false, ['encrypt', 'decrypt']);

                if (true_for_encrypt) {
                    // encrypt and return restult
                    out_data = await crypto.subtle.encrypt({ name: 'AES-CBC', iv: vector }, key_obj, in_data);
                } else {
                    //decrypt
                    out_data = await crypto.subtle.decrypt({ name: 'AES-CBC', iv: vector }, key_obj, in_data.buffer);
                }
            } catch(err) {
                console.log(err);
                return err;
            }
        }

        if (this.dbg_show_encrypt_hash) {
            console.log((true_for_encrypt ? 'enc' : 'dec') + "Hash:  " + sha256.hex(out_data));
        }

        return {
            data: out_data,
            crckey: crckey,
            key: secret_u8,
        };
    },

    crc32: (function() {
        var table = new Uint32Array(256);

        // Pre-generate crc32 polynomial lookup table
        for (var i = 256; i--;) {
            var tmp = i;
            for (var k = 8; k--;) {
                tmp = tmp & 1 ? 3988292384 ^ tmp >>> 1 : tmp >>> 1;
            }
            table[i] = tmp;
        }

        return function(data, first16Konly = false) {
            data = cn2conv.toUint8Array(data);
            if (first16Konly && data.byteLength > 16384) {
                data = new Uint8Array(data.buffer.slice(0,16384));
            }
            var crc = -1;
            for (var i = 0, l = data.length; i < l; i++) {
                crc = crc >>> 8 ^ table[crc & 255 ^ data[i]];
            }
            return (crc ^ -1) >>> 0;
        };
    })(),

};

