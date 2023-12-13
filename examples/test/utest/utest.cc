/**
 * 用户空间自定义程序
*/
#include <iostream>
#include <stdio.h>
#include <unistd.h>

int utest_add(int a, int b)
{
    return a + b;
}

int utest_sub(int a, int b)
{
    return a - b;
}

int main(int argc, char **argv)
{
    int err, i;

    for (i = 0;; i++) {
        utest_add(i, i + 1);
        utest_sub(i * i, i);

        std::cout << "i = " << i << std::endl;

        sleep(1);
    }
}