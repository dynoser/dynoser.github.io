"use sctrict";
if (typeof TextEncoder === "undefined") {
    TextEncoder=function TextEncoder(){};
    TextEncoder.prototype.encode = function encode(str) {
        "use strict";
        var Len = str.length, resPos = -1;
        // The Uint8Array's length must be at least 3x the length of the string because an invalid UTF-16
        //  takes up the equivelent space of 3 UTF-8 characters to encode it properly. However, Array's
        //  have an auto expanding length and 1.5x should be just the right balance for most uses.
        var resArr = typeof Uint8Array === "undefined" ? new Array(Len * 1.5) : new Uint8Array(Len * 3);
        for (var point=0, nextcode=0, i = 0; i !== Len; ) {
            point = str.charCodeAt(i), i += 1;
            if (point >= 0xD800 && point <= 0xDBFF) {
                if (i === Len) {
                    resArr[resPos += 1] = 0xef/*0b11101111*/; resArr[resPos += 1] = 0xbf/*0b10111111*/;
                    resArr[resPos += 1] = 0xbd/*0b10111101*/; break;
                }
                // https://mathiasbynens.be/notes/javascript-encoding#surrogate-formulae
                nextcode = str.charCodeAt(i);
                if (nextcode >= 0xDC00 && nextcode <= 0xDFFF) {
                    point = (point - 0xD800) * 0x400 + nextcode - 0xDC00 + 0x10000;
                    i += 1;
                    if (point > 0xffff) {
                        resArr[resPos += 1] = (0x1e/*0b11110*/<<3) | (point>>>18);
                        resArr[resPos += 1] = (0x2/*0b10*/<<6) | ((point>>>12)&0x3f/*0b00111111*/);
                        resArr[resPos += 1] = (0x2/*0b10*/<<6) | ((point>>>6)&0x3f/*0b00111111*/);
                        resArr[resPos += 1] = (0x2/*0b10*/<<6) | (point&0x3f/*0b00111111*/);
                        continue;
                    }
                } else {
                    resArr[resPos += 1] = 0xef/*0b11101111*/; resArr[resPos += 1] = 0xbf/*0b10111111*/;
                    resArr[resPos += 1] = 0xbd/*0b10111101*/; continue;
                }
            }
            if (point <= 0x007f) {
                resArr[resPos += 1] = (0x0/*0b0*/<<7) | point;
            } else if (point <= 0x07ff) {
                resArr[resPos += 1] = (0x6/*0b110*/<<5) | (point>>>6);
                resArr[resPos += 1] = (0x2/*0b10*/<<6)  | (point&0x3f/*0b00111111*/);
            } else {
                resArr[resPos += 1] = (0xe/*0b1110*/<<4) | (point>>>12);
                resArr[resPos += 1] = (0x2/*0b10*/<<6)    | ((point>>>6)&0x3f/*0b00111111*/);
                resArr[resPos += 1] = (0x2/*0b10*/<<6)    | (point&0x3f/*0b00111111*/);
            }
        }
        if (typeof Uint8Array !== "undefined") return resArr.subarray(0, resPos + 1);
        // else // IE 6-9
        resArr.length = resPos + 1; // trim off extra weight
        return resArr;
    };
    TextEncoder.prototype.toString = function(){return "[object TextEncoder]"};
    try { // Object.defineProperty only works on DOM prototypes in IE8
        Object.defineProperty(TextEncoder.prototype,"encoding",{
            get:function(){if(TextEncoder.prototype.isPrototypeOf(this)) return"utf-8";
                           else throw TypeError("Illegal invocation");}
        });
    } catch(e) { /*IE6-8 fallback*/ TextEncoder.prototype.encoding = "utf-8"; }
    if(typeof Symbol!=="undefined")TextEncoder.prototype[Symbol.toStringTag]="TextEncoder";
}

cn2conv = {
    // ===== Type-convertion functions =====

    /**
     * Convert number into 32-bit without sign
     * 
     * @param {Number} c32
     */
    toUint32: function(c32) {
        if ((c32 & 4294967295) < 0) { // convert to Uint (remove sign)
            c32 = 2147483648 + (2147483647 & c32);
        } else {
            c32 = c32 & 4294967295;
        }
        return c32;
    },

    /**
     * Convert source to numeric-keys array
     * 
     * Examples:
     *   for string: " aaa \n bbb \n ccc " => ['aaa','bbb','ccc']
     *   for obj: {1: 2, 3: 4} => [undefined, 2, undefined, 4]
     *   for arr: [1, 2, 3, 4] => no changes
     *   for UInt16Array([1,2,3,4]) => [1,2,3,4]
     * 
     */
    toNumKeyArr: function(in_data, str_div=false, trim_chars = ",\"'.:;)(][}{") {
        if (typeof in_data === 'string') {
            if (false === str_div) {
                str_div = "\n";
            }
            in_data = in_data.split(str_div).map(v => v.trim()).filter(v => v.length);
            in_data = in_data.map(v => {
                while(v.length && trim_chars.includes(v.substr(-1))) {
                    v = v.substr(0, v.length-1);
                }
                while(v.length && trim_chars.includes(v[0])) {
                    v = v.substr(1);
                }
                return v;
            });
        }
        var num_arr = in_data;
        if ((typeof in_data === 'object') && !Array.isArray(num_arr)) {
            if (typeof in_data.byteLength === 'undefined') {
                num_arr = [];
                Object.keys(in_data).map(key => num_arr[Number(key)] = in_data[key]);
            } else {
                num_arr = Array.from(in_data);
            }
        }
        return num_arr;
    },

    toUint8Array: function(in_data) {
        if (typeof in_data === 'string' || in_data instanceof String) {
            in_data = this.str2buff(in_data);
        } else if (typeof in_data.buffer === 'object') {
            in_data = in_data.buffer;
        }
        if ((in_data instanceof ArrayBuffer) || Array.isArray(in_data)) {
            in_data = new Uint8Array(in_data);
        }
        return in_data;
    },

    in2buff: function(data) {
        let buff;
        if (Array.isArray(data)) {
            let max = data.reduce((max, v) => { return (v>max)? v: max; }, 0);
            if (max < 256) { // maybe data is bytes array
                buff = (new Uint8Array(data)).buffer;
            } else { // maybe data is unicode array
                buff = String.fromCharCode.apply(null, data);
            }
        } else if (data instanceof ArrayBuffer){
            buff = data;
        } else if (typeof data === 'string') {
            buff = this.str2buff(data); // maybe is utf-8 string
        } else { // what else? may be Uint8Array, UInt16Array, etc?
            buff = this.toUint8Array(data);
            if (typeof buff.buffer === 'undefined') {
                return false;
            }
            buff = buff.buffer;
        }
        return buff;
    },

    str2buff: function(str, mode16) {
        var i, bv, sl = str.length;

        // if mode16 not set or < 0 - convert as utf-8
        if ((typeof mode16 === 'undefined') || (mode16 < 0)) {
            var encoder = new TextEncoder();
            bv = encoder.encode(str);
            if (bv.length != bv.buffer.byteLength) {
                bv = bv.buffer.slice(0,bv.length);
                return bv;
            }
            return bv.buffer;
        }
        if (mode16) {
            bv = new Uint16Array(sl);
        } else {
            bv = new Uint8Array(sl);
        }
        for (i = 0; i < sl; i++) {
            bv[i] = str.charCodeAt(i);
        }
        return bv.buffer;
    },

    buff2str: function(data, mode16) {
        // if mode16 not set (or < 0) - convert from utf-8
        if ((typeof mode16 === 'undefined') || (mode16 < 0)) {
            let u8 = this.toUint8Array(data);
            if (typeof TextDecoder === 'undefined') {
                return this.Utf8ArrToStr(u8)
            }
            var decoder = new TextDecoder();
            return decoder.decode(u8);
        }
        if (mode16) {
            return String.fromCharCode.apply(null, new Uint16Array(data));
        } else {
            return String.fromCharCode.apply(null, this.toUint8Array(data));
        }
    },

    Utf8ArrToStr: function(arr) {
        var out, i, len, c;
        var char2, char3;
        out = "";
        len = arr.length;
        i = 0;
        while(i < len) {
            c = arr[i++];
            switch(c >> 4)
            {
                case 0: case 1: case 2: case 3: case 4: case 5: case 6: case 7:
                // 0xxxxxxx
                out += String.fromCharCode(c);
                break;
                case 12: case 13:
                // 110x xxxx   10xx xxxx
                char2 = arr[i++];
                out += String.fromCharCode(((c & 0x1F) << 6) | (char2 & 0x3F));
                break;
                case 14:
                    // 1110 xxxx  10xx xxxx  10xx xxxx
                    char2 = arr[i++];
                    char3 = arr[i++];
                    out += String.fromCharCode(((c & 0x0F) << 12) |
                        ((char2 & 0x3F) << 6) |
                        ((char3 & 0x3F) << 0));
                    break;
            }
        }
        return out;
    },
};