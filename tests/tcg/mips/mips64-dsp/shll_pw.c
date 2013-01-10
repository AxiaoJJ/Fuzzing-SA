#include "io.h"

int main(void)
{
    long long rd, rt, dsp;
    long long result, resultdsp;

    rt        = 0x8765432112345678;
    result    = 0x8765432112345678;
    resultdsp = 0;

    __asm
        ("shll.pw %0, %2, 0x0\n\t"
         "rddsp %1\n\t"
         : "=r"(rd), "=r"(dsp)
         : "r"(rt)
        );

    dsp = (dsp >> 22) & 0x01;
    if ((dsp != resultdsp) || (rd  != result)) {
        printf("shll.pw wrong\n");
        return -1;
    }

    rt        = 0x8765432112345678;
    result    = 0x6543210034567800;
    resultdsp = 1;

    __asm
        ("shll.pw %0, %2, 0x8\n\t"
         "rddsp %1\n\t"
         : "=r"(rd), "=r"(dsp)
         : "r"(rt)
        );

    dsp = (dsp >> 22) & 0x01;
    if ((dsp != resultdsp) || (rd  != result)) {
        printf("shll.pw wrong\n");
        return -1;
    }

    return 0;
}
