// This file was generated automatically by the Snowball to JSX compiler

import "base-stemmer.jsx";
import "among.jsx";

 /**
  * This class was automatically generated by a Snowball to JSX compiler
  * It implements the stemming algorithm defined by a snowball script.
  */

class NorwegianStemmer extends BaseStemmer
{
    static const serialVersionUID = 1;
    static const methodObject = new NorwegianStemmer();

    static const a_0 = [
        new Among("a", -1, 1),
        new Among("e", -1, 1),
        new Among("ede", 1, 1),
        new Among("ande", 1, 1),
        new Among("ende", 1, 1),
        new Among("ane", 1, 1),
        new Among("ene", 1, 1),
        new Among("hetene", 6, 1),
        new Among("erte", 1, 3),
        new Among("en", -1, 1),
        new Among("heten", 9, 1),
        new Among("ar", -1, 1),
        new Among("er", -1, 1),
        new Among("heter", 12, 1),
        new Among("s", -1, 2),
        new Among("as", 14, 1),
        new Among("es", 14, 1),
        new Among("edes", 16, 1),
        new Among("endes", 16, 1),
        new Among("enes", 16, 1),
        new Among("hetenes", 19, 1),
        new Among("ens", 14, 1),
        new Among("hetens", 21, 1),
        new Among("ers", 14, 1),
        new Among("ets", 14, 1),
        new Among("et", -1, 1),
        new Among("het", 25, 1),
        new Among("ert", -1, 3),
        new Among("ast", -1, 1)
    ];

    static const a_1 = [
        new Among("dt", -1, -1),
        new Among("vt", -1, -1)
    ];

    static const a_2 = [
        new Among("leg", -1, 1),
        new Among("eleg", 0, 1),
        new Among("ig", -1, 1),
        new Among("eig", 2, 1),
        new Among("lig", 2, 1),
        new Among("elig", 4, 1),
        new Among("els", -1, 1),
        new Among("lov", -1, 1),
        new Among("elov", 7, 1),
        new Among("slov", 7, 1),
        new Among("hetslov", 9, 1)
    ];

    static const g_v = [17, 65, 16, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 48, 0, 128] : int[];

    static const g_s_ending = [119, 125, 149, 1] : int[];

    var I_x : int = 0;
    var I_p1 : int = 0;

    function copy_from (other : NorwegianStemmer) : void
    {
        this.I_x = other.I_x;
        this.I_p1 = other.I_p1;
        super.copy_from(other);
    }

    function r_mark_regions () : boolean
    {
        var v_1 : int;
        var v_2 : int;
        // (, line 26
        this.I_p1 = this.limit;
        // test, line 30
        v_1 = this.cursor;
        // (, line 30
        // hop, line 30
        {
            var c : int = this.cursor + 3;
            if (0 > c || c > this.limit)
            {
                return false;
            }
            this.cursor = c;
        }
        // setmark x, line 30
        this.I_x = this.cursor;
        this.cursor = v_1;
        // goto, line 31
        golab0: while(true)
        {
            v_2 = this.cursor;
            var lab1 = true;
            lab1: while (lab1 == true)
            {
                lab1 = false;
                if (!(this.in_grouping(NorwegianStemmer.g_v, 97, 248)))
                {
                    break lab1;
                }
                this.cursor = v_2;
                break golab0;
            }
            this.cursor = v_2;
            if (this.cursor >= this.limit)
            {
                return false;
            }
            this.cursor++;
        }
        // gopast, line 31
        golab2: while(true)
        {
            var lab3 = true;
            lab3: while (lab3 == true)
            {
                lab3 = false;
                if (!(this.out_grouping(NorwegianStemmer.g_v, 97, 248)))
                {
                    break lab3;
                }
                break golab2;
            }
            if (this.cursor >= this.limit)
            {
                return false;
            }
            this.cursor++;
        }
        // setmark p1, line 31
        this.I_p1 = this.cursor;
        // try, line 32
        var lab4 = true;
        lab4: while (lab4 == true)
        {
            lab4 = false;
            // (, line 32
            if (!(this.I_p1 < this.I_x))
            {
                break lab4;
            }
            this.I_p1 = this.I_x;
        }
        return true;
    }

    function r_main_suffix () : boolean
    {
        var among_var : int;
        var v_1 : int;
        var v_2 : int;
        var v_3 : int;
        // (, line 37
        // setlimit, line 38
        v_1 = this.limit - this.cursor;
        // tomark, line 38
        if (this.cursor < this.I_p1)
        {
            return false;
        }
        this.cursor = this.I_p1;
        v_2 = this.limit_backward;
        this.limit_backward = this.cursor;
        this.cursor = this.limit - v_1;
        // (, line 38
        // [, line 38
        this.ket = this.cursor;
        // substring, line 38
        among_var = this.find_among_b(NorwegianStemmer.a_0, 29);
        if (among_var == 0)
        {
            this.limit_backward = v_2;
            return false;
        }
        // ], line 38
        this.bra = this.cursor;
        this.limit_backward = v_2;
        switch (among_var) {
            case 0:
                return false;
            case 1:
                // (, line 44
                // delete, line 44
                if (!this.slice_del())
                {
                    return false;
                }
                break;
            case 2:
                // (, line 46
                // or, line 46
                var lab0 = true;
                lab0: while (lab0 == true)
                {
                    lab0 = false;
                    v_3 = this.limit - this.cursor;
                    var lab1 = true;
                    lab1: while (lab1 == true)
                    {
                        lab1 = false;
                        if (!(this.in_grouping_b(NorwegianStemmer.g_s_ending, 98, 122)))
                        {
                            break lab1;
                        }
                        break lab0;
                    }
                    this.cursor = this.limit - v_3;
                    // (, line 46
                    // literal, line 46
                    if (!(this.eq_s_b(1, "k")))
                    {
                        return false;
                    }
                    if (!(this.out_grouping_b(NorwegianStemmer.g_v, 97, 248)))
                    {
                        return false;
                    }
                }
                // delete, line 46
                if (!this.slice_del())
                {
                    return false;
                }
                break;
            case 3:
                // (, line 48
                // <-, line 48
                if (!this.slice_from("er"))
                {
                    return false;
                }
                break;
        }
        return true;
    }

    function r_consonant_pair () : boolean
    {
        var v_1 : int;
        var v_2 : int;
        var v_3 : int;
        // (, line 52
        // test, line 53
        v_1 = this.limit - this.cursor;
        // (, line 53
        // setlimit, line 54
        v_2 = this.limit - this.cursor;
        // tomark, line 54
        if (this.cursor < this.I_p1)
        {
            return false;
        }
        this.cursor = this.I_p1;
        v_3 = this.limit_backward;
        this.limit_backward = this.cursor;
        this.cursor = this.limit - v_2;
        // (, line 54
        // [, line 54
        this.ket = this.cursor;
        // substring, line 54
        if (this.find_among_b(NorwegianStemmer.a_1, 2) == 0)
        {
            this.limit_backward = v_3;
            return false;
        }
        // ], line 54
        this.bra = this.cursor;
        this.limit_backward = v_3;
        this.cursor = this.limit - v_1;
        // next, line 59
        if (this.cursor <= this.limit_backward)
        {
            return false;
        }
        this.cursor--;
        // ], line 59
        this.bra = this.cursor;
        // delete, line 59
        if (!this.slice_del())
        {
            return false;
        }
        return true;
    }

    function r_other_suffix () : boolean
    {
        var among_var : int;
        var v_1 : int;
        var v_2 : int;
        // (, line 62
        // setlimit, line 63
        v_1 = this.limit - this.cursor;
        // tomark, line 63
        if (this.cursor < this.I_p1)
        {
            return false;
        }
        this.cursor = this.I_p1;
        v_2 = this.limit_backward;
        this.limit_backward = this.cursor;
        this.cursor = this.limit - v_1;
        // (, line 63
        // [, line 63
        this.ket = this.cursor;
        // substring, line 63
        among_var = this.find_among_b(NorwegianStemmer.a_2, 11);
        if (among_var == 0)
        {
            this.limit_backward = v_2;
            return false;
        }
        // ], line 63
        this.bra = this.cursor;
        this.limit_backward = v_2;
        switch (among_var) {
            case 0:
                return false;
            case 1:
                // (, line 67
                // delete, line 67
                if (!this.slice_del())
                {
                    return false;
                }
                break;
        }
        return true;
    }

    override function stem () : boolean
    {
        var v_1 : int;
        var v_2 : int;
        var v_3 : int;
        var v_4 : int;
        // (, line 72
        // do, line 74
        v_1 = this.cursor;
        var lab0 = true;
        lab0: while (lab0 == true)
        {
            lab0 = false;
            // call mark_regions, line 74
            if (!this.r_mark_regions())
            {
                break lab0;
            }
        }
        this.cursor = v_1;
        // backwards, line 75
        this.limit_backward = this.cursor; this.cursor = this.limit;
        // (, line 75
        // do, line 76
        v_2 = this.limit - this.cursor;
        var lab1 = true;
        lab1: while (lab1 == true)
        {
            lab1 = false;
            // call main_suffix, line 76
            if (!this.r_main_suffix())
            {
                break lab1;
            }
        }
        this.cursor = this.limit - v_2;
        // do, line 77
        v_3 = this.limit - this.cursor;
        var lab2 = true;
        lab2: while (lab2 == true)
        {
            lab2 = false;
            // call consonant_pair, line 77
            if (!this.r_consonant_pair())
            {
                break lab2;
            }
        }
        this.cursor = this.limit - v_3;
        // do, line 78
        v_4 = this.limit - this.cursor;
        var lab3 = true;
        lab3: while (lab3 == true)
        {
            lab3 = false;
            // call other_suffix, line 78
            if (!this.r_other_suffix())
            {
                break lab3;
            }
        }
        this.cursor = this.limit - v_4;
        this.cursor = this.limit_backward;        return true;
    }

    function equals (o : variant) : boolean {
        return o instanceof NorwegianStemmer;
    }

    function hashCode() : int
    {
        //http://stackoverflow.com/questions/194846/is-there-any-kind-of-hashcode-function-in-javascript
        var classname = "NorwegianStemmer";
        var hash = 0;
        if (classname.length == 0) return hash;
        for (var i = 0; i < classname.length; i++) {
            var char = classname.charCodeAt(i);
            hash = ((hash << 5) - hash) + char;
            hash = hash & hash; // Convert to 32bit integer
        }
        return hash;
    }

}

