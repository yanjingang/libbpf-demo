/**
 * 用户空间自定义程序
*/
#include <iostream>
#include <stdio.h>
#include <unistd.h>

namespace test {

class UTest {
public:
    UTest(){
        std::cout << "UTest constructor" << std::endl;
    }

    int utest_add(int a, int b)
    {
        std::cout << "utest_add a = " << a << " b = " << b << std::endl;
        return a + b;
    }

    int utest_sub(int a, int b)
    {
        return a - b;
    }
};

}  // namespace test