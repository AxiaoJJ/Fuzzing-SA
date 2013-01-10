#include<stdio.h>
#include<assert.h>

int main()
{
    int rd, rs, rt;
    int dsp;
    int result;

    rs         = 0x11777066;
    rt         = 0x55AA70FF;
    result     = 0x0F;
    __asm
        ("cmpgdu.le.qb %0, %2, %3\n\t"
         "rddsp %1\n\t"
         : "=r"(rd), "=r"(dsp)
         : "r"(rs), "r"(rt)
        );
    dsp = (dsp >> 24) & 0x0F;
    assert(rd  == result);
    assert(dsp == result);

    rs     = 0x11777066;
    rt     = 0x11707066;
    result = 0x0B;
    __asm
        ("cmpgdu.le.qb %0, %2, %3\n\t"
         "rddsp %1\n\t"
         : "=r"(rd), "=r"(dsp)
         : "r"(rs), "r"(rt)
        );
    dsp = (dsp >> 24) & 0x0F;
    assert(rd  == result);
    assert(dsp == result);

    return 0;
}
