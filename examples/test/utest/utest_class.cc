/**
 * 用户空间自定义程序
*/
#include <memory>
#include "utest_class.h"

using namespace test;

int main(int argc, char **argv)
{
    int err, i;
    auto obj = std::make_shared<UTest>();

    for (i = 0;; i++) {
        std::cout << "i = " << i << std::endl;

        obj->utest_add(i, i + 1);
        obj->utest_sub(i * i, i);

        sleep(1);
    }
}