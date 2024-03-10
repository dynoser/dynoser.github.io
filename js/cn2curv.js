"use sctrict";

cn2curv = {
    // ===== CIRCON2 Curves-alg =====

    // maximal supported basis for curves-encoding
    maxbasis: 15,

    // upper limits for 1,2,4 and 8 bytes encode (bigint)
    FMT: [
        256n,
        65536n,
        4294967296n,
        9223372036854775807n,
    ],

    curves_encode: function(basis, parts, data_buff) {
        if (!(data_buff instanceof ArrayBuffer)) {
            return "ArrayBuffer required";
        }

        // define vars
        var n, i, j, k, r, s, f, y;

        // calculate factorial array
        var fcl = [BigInt(1)];
        for (n = 1; n <= basis; n++) {
            fcl[n] = fcl[n - 1] * BigInt(n);
        }

        // convert data_buff to UInt8Arraу
        var data = new Uint8Array(data_buff);
        var bytes_cnt = data.byteLength;

        // check input parameters
        if ((typeof parts !== 'number') || (typeof basis != 'number') || bytes_cnt === 0 ||
            parts < 3 || basis < 2 || basis > this.maxbasis) return "Bad parameters";

        // generate random bytes UInt8Arraу
        var rnd = window.crypto.getRandomValues(new Uint8Array(bytes_cnt));

        // create empty arr of n elements
        var arr = [];
        for (n = 0; n < parts; n++) {
            arr[n] = [];
        }

        // prepare hindrances array
        var dn = new Uint8Array(basis + 1);

        for (i = 0; i < bytes_cnt; i++) {
            r = rnd[i];
            s = data[i] ^ r;

            // calculate circular distance between two points (r,s)
            dn[1] = ((r & 15) * 16) + (s >>> 4);
            r = (r & 240) + (s & 15);
            r += Math.floor(Math.random() * 128) * 256;

            // generate random hindrances
            for (j = 2; j <= basis; j++) {
                dn[j] = Math.floor(Math.random() * 200) + 1;
            }

            // calculate Y-points array
            for (n = 0; n < parts; n++) {
                y = BigInt(r);
                for (j = 1; j < basis; j++) {
                    f = BigInt(dn[j]);
                    for (k = 0; k < j; k++) {
                        f *= BigInt(n + k);
                    }
                    y += f / fcl[j];
                }
                arr[n].push(y);
            }
        }
        // calculate crc32 or zero-points
        arr[0] = circon2.crc32(this.bigintarr2buff(arr[0]));
        return arr;
    },

    curves_decode: function(arr) {
        if (!Array.isArray(arr)) {
            return false;
        }
        let i, k, n, ellen = -1;
        let ya = [];
        let na = Object.keys(arr);
        // convert keys from string to number
        na.forEach((v, i) => { 
            k = Number(v);
            if (k) {
                na[i] = k;
            } else {
                delete(na[v]);
            }
        });
        na.sort();
        let elcnt = 0;
        na.forEach((k, n) => {
            ya.push(arr[k]);
            i = ya[n].length;
            if (ellen < 0) ellen = i;
            if (ellen != i) {
                return false;
            }
            elcnt++;
        });
        if (elcnt < 2 || elcnt > this.maxbasis) {
            return false;
        }

        // calculate factorial array
        let fcl = [BigInt(1)];
        for (n = 1; n <= this.maxbasis; n++) {
            fcl[n] = fcl[n - 1] * BigInt(n);
        }

        let prc = 1000000000000n;
        let prcs = 100000000000n;
        let r, y, j, f, d, w, z, cz, pr, str = new Uint8Array(ellen);
        let zero = [];
        for (k = 0; k < ellen; k++) {

            // filling pr[0] as Y-array
            pr = [];
            pr.push([]);
            for (i = 0; i < elcnt; i++) {
                pr[0].push(BigInt(ya[i][k]) * prc);
            }

            // calculate derivatives pr[1], pr[2],...
            z = 0;
            while ((typeof pr[z] !== 'undefined') && (pr[z].length > 1)) {
                cz = pr[z].length - 1;
                for (i = 0; i < cz; i++) {
                    if (typeof pr[z + 1] === 'undefined') {
                        pr.push([]);
                    }
                    pr[z + 1][i] =
                        BigInt(z + 1) * (pr[z][i + 1] - pr[z][i]) / BigInt(na[i + 1 + z] - na[i]);
                }
                z++;
            }

            for (w = this.maxbasis; w > 1; w--) {
                if ((typeof pr[w] === 'undefined') || (pr[w][0] < prcs)) {
                    continue;
                }
                d = pr[w][0];

                // change Y-array
                for (i = 0; i < elcnt; i++) {
                    f = d;
                    n = na[i];
                    for (j = 0; j < w; j++) {
                        f *= BigInt(n + j);
                    }
                    pr[0][i] -= (f / fcl[w]);
                }

                // re-calculate all derivatives
                z = 0;
                while ((typeof pr[z] !== 'undefined') && (pr[z].length > 1)) {
                    cz = pr[z].length - 1;
                    for (i = 0; i < cz; i++) {
                        pr[z + 1][i] = BigInt(z + 1) * (pr[z][i + 1] - pr[z][i]) / BigInt(na[i + 1 + z] - na[i]);
                    }
                    z++;
                }
            }

            // calculate distance between first and second keys
            dif_key = na[1] - na[0];

            // recover d and y from base-2
            d = Number(((pr[0][1] - pr[0][0]) / BigInt(dif_key)) / prc);
            y = Number(pr[0][0] / prc) - d * na[0];
            // recover r
            r = (y & 240) + ((d & 240) >>> 4);
            // recover s
            s = (d % 16) * 16 + y % 16;
            s = s ^ r;

            zero[k] = y;
            str[k] = s;
        }
        crc32z = circon2.crc32(this.bigintarr2buff(zero));
        return {
            crc32z: crc32z,
            data: str
        };
    },
    
    bigintarr2buff: function(arr) {
        let l = arr.length;
        let crcbuff = new ArrayBuffer(l * 8);
        let crcview = new DataView(crcbuff);
        for(let i=0; i<l; i++) {
            crcview.setBigUint64(i*8, BigInt(arr[i]));
        }
        return crcbuff;
    },
};
