#include "io.h"

int main(void)
{
    long long rd, rs, rt;
    long long res;

    rs = 0x1234567812345678;
    rt = 0x8765432187654321;

    res = 0x3478347865216521;

    __asm
        ("precr.ob.qh %0, %1, %2\n\t"
         : "=r"(rd)
         : "r"(rs), "r"(rt)
        );

    if (rd != res) {
        printf("precr.ob.qh error\n");
        return -1;
    }

    return 0;
}
