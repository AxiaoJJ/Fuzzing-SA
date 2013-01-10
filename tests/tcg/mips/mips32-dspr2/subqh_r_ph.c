#include<stdio.h>
#include<assert.h>

int main()
{
    int rd, rs, rt;
    int result;

    rs = 0x12345678;
    rt = 0x87654321;
    result = 0x456809AC;

    __asm
        ("subqh_r.ph %0, %1, %2\n\t"
         : "=r"(rd)
         : "r"(rs), "r"(rt)
        );
    assert(rd == result);

    return 0;
}
