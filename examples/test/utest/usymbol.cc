/**
 * 导出自定义程序的符号表
 *      ./usymbol utest > symbols.txt
*/
#include <fstream>
#include <iomanip>
#include <cxxabi.h>
#include <stdio.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <unistd.h>
#include <libelf.h>
#include <gelf.h>
#include "proto/symbol.pb.h"

int main(int argc, char **argv) {
    const char kMangledSymbolPrefix[] = "_Z";
    const char kSymbolCharacters[] = "abcdefghijklmnopqrstuvwxyz" \
                                     "ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789_";

    // init proto symbols map
    auto symbol = new Symbol();
    auto& symbolMap = *symbol->mutable_symbols();

    elf_version(EV_CURRENT);

    // each all bin or so file
    for (int j = 1; j < argc; j++) {
        std::cerr << "dump symbols: " << argv[j] << "\n";
        GElf_Shdr shdr;

        int fd = open(argv[j], O_RDONLY);
        if (fd < 0) {
            std::cerr << "failed to open: " << argv[j] << "\n";
            return 0; 
        }
        // load elf info
        Elf *elf = elf_begin(fd, ELF_C_READ, NULL);
        Elf_Scn *scn = NULL;
        // find symbol table
        while ((scn = elf_nextscn(elf, scn)) != NULL) {
            gelf_getshdr(scn, &shdr);
            if (shdr.sh_type == SHT_SYMTAB) {
                break;
            }
        }
        if (!scn) {
            // find symbol table in dynamic section
            while ((scn = elf_nextscn(elf, scn)) != NULL) {
                gelf_getshdr(scn, &shdr);
                if (shdr.sh_type == SHT_DYNSYM) {
                    break;
                }
            }
        }
        
        // start reading symbol table
        Elf_Data *data = elf_getdata(scn, NULL);
        int count = shdr.sh_size / shdr.sh_entsize;
        for (int i = 0; i < count; ++i) {
            GElf_Sym sym;
            gelf_getsym(data, i, &sym);

            // only dump function symbol
            if (sym.st_shndx == SHN_UNDEF || (sym.st_shndx != SHN_UNDEF && ELF64_ST_TYPE(sym.st_info) != STT_FUNC)) {
                continue;
            }

            char* s = elf_strptr(elf, shdr.sh_link, sym.st_name);
            if (strlen(s) > 0) {
                std::string symbol(s);
                // set when not _Zxxx symbol
                std::string::size_type s = symbol.find(kMangledSymbolPrefix);
                if (s == std::string::npos) {
                    symbolMap[symbol] = sym.st_value;
                    // std::cout << "Add SymbolMap: " << symbol << std::endl;
                    continue;
                }

                // clear _Zxxx func symbol name
                std::string::size_type e = symbol.find_first_not_of(kSymbolCharacters, s);
                int32_t status = 1;
                char* name = abi::__cxa_demangle(symbol.substr(s, e - s).c_str(), NULL, NULL, &status);
                if (name != nullptr) {
                    symbolMap[name] = sym.st_value;
                    // std::cout << "Add SymbolMap _Z: " << symbol << std::endl;
                } else {
                    // FIXME:
                    //std::cout << "failed to demangle: "  << symbol << std::endl;
                }   
            }    
        }

        elf_end(elf);
        close(fd);
    }

    // dump symbol map to file
    std::ofstream os("./symbols.dump", std::ios::binary);
    symbol->SerializeToOstream(&os);
    os.close();

    // test load symbols from file
    std::ifstream is("./symbols.dump", std::ios::binary);
    symbol = new Symbol();
    symbol->ParseFromIstream(&is);
    is.close();
    symbolMap = symbol->symbols();

    // print symbol map
    for (auto& x : symbolMap) {
        std::cout << std::hex << std::setw(8) << x.second  << " : " << x.first << std::endl;
    }
}
