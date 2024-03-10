"use sctrict";

cn2scar = {
    // ===== CIRCON2 binary-scarcity algorithm =====

   calc_frag_len: function (parts, surplus, num, part_len, alg) {
    let n = Number(num);
    let frag_n = n - 1; // actual fragment number by n [0..parts-1]

    // how many fragments contain one part
    let frags_in_part = (alg > 0) ? alg : parts - 1;

    // start base-fragment-length calculate.
    let base_frag_len = Number(Math.floor(part_len / frags_in_part));

    // subtract 1 if all available fragments are less than surplus
    if (surplus) { // these action make sense only if non-zero surplus
        if (
            (alg === 1 && frag_n < surplus) ||   // only one fragment and it is in the surplus-range: . f s ...
            (alg === 2 && n && n < surplus) ||  // two fragments less then surplus: . f n s ...
            (alg === -1 && frag_n === surplus && frag_n === parts - 1) // if the last fragment is missing and surplus without it
        ) {
            base_frag_len--;
        }
    }

    // how many bytes had data before divide?
    let full_len = base_frag_len * parts + surplus;
    // full_len, base_frag_len, frags_in_part, frag_n
    return {
        full_len: full_len,
        base_frag_len: base_frag_len,
        frags_in_part: frags_in_part,
        frag_n: frag_n
    };
},

scarcity_div: function(parts, data_for_divide = false, alg = -1, base_part_len = 8) {
    if (base_part_len < 0 || parts < 1) {
        return "Illegal parameters";
    }

    // No data => creating random string (secure key)
    if (data_for_divide === false) {
        if (!base_part_len) {
            return "No data-for-divide and no base-part-len";
        }
        data_for_divide = circon2.random_bytes(base_part_len * parts);
    }

    let data_u8 = cn2conv.toUint8Array(data_for_divide);
    
    if (typeof data_u8 !== 'object' || typeof data_u8.byteLength === 'undefined') {
        return "Bad source data type";
    }
    if (typeof data_u8.length !== 'number' || data_u8.length !== data_u8.byteLength) {
        return "Bad source data type";
    }

    let data_len = data_u8.length;
    let surplus = data_len % parts;
    let inverse = (alg > 0); // 1, 2

    // calculate base_frag_len and sur_frag_len
    let base_frag_len = (data_len - surplus) / parts;
    if (!base_frag_len) {
        return "Too small data. Source data must have bytes greater than parts.";
    }
    let sur_frag_len = base_frag_len + 1;

    let place_p, sumarr;

    // create all-fragments-array
    let all_frag_arr = [];
    let frag_n = 0, p = 0;
    while (p < data_len) {
        frag_len = (frag_n++ < surplus) ? sur_frag_len : base_frag_len;
        all_frag_arr.push(data_u8.slice(p, p + frag_len));
        p += frag_len;
    }

    // [0] => source data, [1] = first part, [2] = second part, ...
    let scarcity_arr = [data_u8];
    // zero-place pointer rotate from 0
    for (num = 1; num <= parts; num++) {
        sumarr = [];
        // push non-zero fragments to $scarity_arr for each part
        for(place_p = 0; place_p < all_frag_arr.length; place_p++) {
            if ((place_p != (num - 1)) ^ inverse) { // skip zero-place
                sumarr = sumarr.concat(Array.from(all_frag_arr[place_p]));
                if (inverse) {
                    if (alg > 1) {
                        place_p = num % parts;
                        sumarr = sumarr.concat(Array.from(all_frag_arr[place_p]));
                    }
                    break;
                }
            }
        }
        scarcity_arr.push(new Uint8Array(sumarr));
    }

    return scarcity_arr;
},

scarcity_sum: function(in_obj_or_arr, parts, surplus = 0, alg = -1) {
    var scarcity_arr = cn2conv.toNumKeyArr(in_obj_or_arr);
    if (!Array.isArray(scarcity_arr) || typeof parts !== 'number' || typeof surplus !== 'number' || typeof alg !== 'number') {
        return "Invalid parameter type";
    }
    if (!scarcity_arr.length || parts < 1 || surplus < 0 || surplus >= parts || alg < -1 || alg > 2) {
        return "Illegal parameter value";
    }

    // check parts_arr and move elements to $arr
    let full_len_arr = [];
    scarcity_arr.forEach((n_part_str, num) => {
        // Only numeric keys. Ignore zero-key.
        if ((typeof num === 'number') && (num > 0)) {
            num = Number(num);
            if (num <= parts) {
                let cl = this.calc_frag_len(parts, surplus, num, n_part_str.byteLength, alg);
                full_len_arr[num] = cl.full_len;
            }
        }
    });


    // search length, which occurs most often:
    let versizes = {};
    let top_cnt = 0, full_data_len;
    full_len_arr.forEach((len, num) => {
        if (typeof versizes[len] === 'undefined') {
            versizes[len] = 1;
        } else {
            versizes[len]++;
        }
        if (versizes[len] > top_cnt) {
            top_cnt = versizes[len];
            full_data_len = len;
        }
    });

    // how many parts required?
    let min_parts = 2;
    if (alg > 0) {
        min_parts = parts - alg + 1;
    }
    if (top_cnt < min_parts) {
        return "Lack parts with equal target-data-sizes";
    }

    // calc base fragment length
    let base_frag_len = Number(Math.floor(full_data_len / parts));
    // calc surplus fragment length
    let sur_frag_len = base_frag_len + 1;

    // Combine all fragments
    let all_frags = {};


    full_len_arr.forEach((size, num) => {
        if (size === full_data_len) { //skip bad-size-parts 
            n_part_str = scarcity_arr[num];
            frag_n = num - 1;

            if (alg < 1) { // -1 fragment
                p = 0;
                frag_len = sur_frag_len;
                for(n = 0; n < parts; n++) {
                    if (n === surplus) frag_len--;
                    if (n !== frag_n) {
                        if (typeof all_frags[n] === 'undefined') {
                            all_frags[n] = {};
                        }
                        all_frags[n][num] = n_part_str.slice(p, p + frag_len);
                        p += frag_len;
                    }
                }
            } else {
                if (typeof all_frags[frag_n] === 'undefined') {
                    all_frags[frag_n] = {};
                }
                if (alg === 1) { // 1 fragment
                    all_frags[frag_n][num] = n_part_str;
                } else { // 2 fragments
                    frag_len = (frag_n < surplus) ? sur_frag_len : base_frag_len;
                    all_frags[frag_n][num] = n_part_str.slice(0, frag_len);;
                    frag_n = (frag_n + 1) % parts; //переместимся на следующий фрагмент
                    if (typeof all_frags[frag_n] === 'undefined') {
                        all_frags[frag_n] = {};
                    }
                    all_frags[frag_n][num] = n_part_str.slice(frag_len);
                }
            }
        }
    });

    // Join all fragments
    let res_arr = [];
    for(frag_n = 0; frag_n < parts; frag_n++) {
        let a = all_frags[frag_n];
        for (let [key, frag] of Object.entries(a)) {
            if (frag instanceof ArrayBuffer) {
                frag = new Uint8Array(frag);
            }
            res_arr = res_arr.concat(Array.from(frag));
            break;
        }
    };

    return new Uint8Array(res_arr);
},
};