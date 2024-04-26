#include <glib.h>
extern "C"{
    #include <qemu/qemu-plugin.h>
    
}
#include <dlfcn.h>
#include <string>
#include <cstring>
#include <fstream>
#include <iostream>
#include <optional>
#include <set>
#include <utility>
#include <iomanip>

QEMU_PLUGIN_EXPORT int qemu_plugin_version = QEMU_PLUGIN_VERSION;

using namespace std;

typedef bool (*arch_supported_fn)(const char *);
typedef bool (*is_indirect_branch_fn)(uint8_t *, size_t);

arch_supported_fn arch_supported;
is_indirect_branch_fn is_indirect_branch;

static optional<uint64_t> branch_addr = {};
static std::set<std::pair<uint64_t, uint64_t>> recorded_pairs;

static ofstream outfile;
typedef struct image_offset {
    uint64_t offset;
    size_t image_name_pos;
} image_offset;

/*
static void print_register_values() {
    outfile << "Register values at indirect branch:" << endl;
    outfile << "RAX: 0x" << hex << qemu_plugin_read_register(reg, buf) << endl;
}
*/
/*
void *read_memory_from_register(GByteArray *buffer, qemu_plugin_register *reg) {
    if (qemu_plugin_read_register(reg, buffer) != -1) {
        // 假设寄存器值是一个有效的地址
        uintptr_t addr = *(uintptr_t*)buffer->data;
        char* memory_content = (char*) addr;  
        return memory_content;
    }
    return nullptr;
}

// 主函数，读取 r0 到 r4 的寄存器值，并尝试读取它们指向的内存
void read_registers_and_memory() {
    GArray *regs = qemu_plugin_get_registers();
    GByteArray *buffer = g_byte_array_new();
    const char *register_names[] = {"r0", "r1", "r2", "r3", "r4"};

    for (int i = 0; i < 5; i++) {
        for (int j = 0; j < regs->len; j++) {
            qemu_plugin_reg_descriptor *desc = &g_array_index(regs, qemu_plugin_reg_descriptor, j);
            if (strcmp(desc->name, register_names[i]) == 0) {
                char* memory_content = static_cast<char*>(read_memory_from_register(buffer, (qemu_plugin_register*)desc->handle));
                if (memory_content != nullptr) {
                    cout << "Memory content at address stored in " << register_names[i] << ": " << *memory_content << endl;
                    outfile << '[' << register_names[i] <<  "]: " << *memory_content << endl;
                } else {
                    cout << "Failed to read memory content for " << register_names[i] << endl;
                    outfile << register_names[i] << ": " << *memory_content << endl;
                }
                break;
            }
        }
    }

    g_byte_array_free(buffer, TRUE);
    g_array_free(regs, TRUE);
}
*/
static optional<image_offset> guest_vaddr_to_offset(const string_view maps_entry, uint64_t guest_vaddr) {
    uint32_t name_pos;
    uint64_t start, end, file_load_offset;

    uint64_t host_vaddr = guest_vaddr + qemu_plugin_guest_base();

    sscanf(maps_entry.data(), "%lx-%lx %*c%*c%*c%*c %lx %*lx:%*lx %*lu %n", &start, &end, &file_load_offset,
           &name_pos);

    if ((start <= host_vaddr) && (host_vaddr <= end)) {
        uint64_t segment_offset = host_vaddr - start;
        uint64_t file_offset = segment_offset + file_load_offset;
        struct image_offset offset = {
            .offset = file_offset,
            .image_name_pos = name_pos,
        };
        return offset;
    }
    return {};
}

// 记录间接分支的源地址和目标地址
static void mark_indirect_branch(uint64_t callsite_vaddr, uint64_t dst_vaddr) {
    ifstream maps("/proc/self/maps");
    string line;
    optional<image_offset> callsite = {};
    optional<image_offset> dst = {};
    string callsite_image = "";
    string dst_image = "";
    while (getline(maps, line)) {
        if (!callsite.has_value()) {
            callsite = guest_vaddr_to_offset(line, callsite_vaddr);
            if (callsite.has_value()) {
                char *image_name = line.data() + callsite->image_name_pos;
                callsite_image = string(image_name);
            }
        }
        if (!dst.has_value()) {
            dst = guest_vaddr_to_offset(line, dst_vaddr);
            if (dst.has_value()) {
                char *image_name = line.data() + dst->image_name_pos;
                dst_image = string(image_name);
            }
        }
        if (callsite.has_value() && dst.has_value()) {
            break;
        }
    }
    if (!callsite.has_value()) {
        cout << "ERROR: Unable to find callsite address in /proc/self/maps" << endl;
    }
    if (!dst.has_value()) {
        cout << "ERROR: Unable to find destination address in /proc/self/maps" << endl;
    }

    auto pair = std::make_pair(callsite_vaddr, dst_vaddr);
    if (recorded_pairs.find(pair) == recorded_pairs.end()) {
        recorded_pairs.insert(pair);
        if(callsite_image.find("lib") == std::string::npos && dst_image.find("lib") == std::string::npos){
            outfile << "0x" << hex << callsite->offset << ",";
            outfile << "0x" << hex << dst->offset << ",";
            outfile << "0x" << hex << callsite_vaddr << ",";
            outfile << "0x" << hex << dst_vaddr << ",";
            outfile << callsite_image << ",";
            outfile << dst_image << endl;
            
        }
    }
    return;
};

static void branch_taken(unsigned int vcpu_idx, void *dst_vaddr) {      //对于每个基本块的开头，检测branch_addr是否有值
    if (branch_addr.has_value()) {
        mark_indirect_branch(branch_addr.value(), (uint64_t)dst_vaddr);
        branch_addr = {};
    }
}

static void branch_skipped(unsigned int vcpu_idx, void *userdata) { branch_addr = {}; }

// Callback for indirect branch insn
static void indirect_branch_exec(unsigned int vcpu_idx, void *callsite_addr) {
    branch_addr = (uint64_t)callsite_addr;      //记录间接跳转的源地址
}

// Callback for indirect branch which may also be the destination of another branch
static void indirect_branch_at_start(unsigned int vcpu_idx, void *callsite_addr) {
    branch_taken(vcpu_idx, callsite_addr);
    indirect_branch_exec(vcpu_idx, callsite_addr);
}

// 对每个基本块执行回调函数
static void block_trans_handler(qemu_plugin_id_t id, struct qemu_plugin_tb *tb) {
    uint64_t start_vaddr = qemu_plugin_tb_vaddr(tb);
    size_t num_insns = qemu_plugin_tb_n_insns(tb);

    for (size_t i = 0; i < num_insns; i++) {
        struct qemu_plugin_insn *insn = qemu_plugin_tb_get_insn(tb, i);
        uint64_t insn_addr = qemu_plugin_insn_vaddr(insn);  //获取块中每条指令的虚拟地址

        uint8_t *insn_data = (uint8_t *)qemu_plugin_insn_data(insn);
        size_t insn_size = qemu_plugin_insn_size(insn);

        bool insn_is_branch = is_indirect_branch(insn_data, insn_size);
        if (i == 0) {
            if (!insn_is_branch) {
                qemu_plugin_register_vcpu_insn_exec_cb(insn, branch_taken, QEMU_PLUGIN_CB_R_REGS,
                                                       (void *)start_vaddr);        //对每条指令的回调函数，检测是不是间接调用跳转过来的
            } else {
                qemu_plugin_register_vcpu_insn_exec_cb(insn, indirect_branch_at_start,
                                                       QEMU_PLUGIN_CB_R_REGS, (void *)start_vaddr);
                if (num_insns > 1) {
                    struct qemu_plugin_insn *next_insn = qemu_plugin_tb_get_insn(tb, 1);
                    qemu_plugin_register_vcpu_insn_exec_cb(next_insn, branch_skipped,
                                                           QEMU_PLUGIN_CB_R_REGS, NULL);
                }
            }
        } else {
            if (insn_is_branch) {
                qemu_plugin_register_vcpu_insn_exec_cb(insn, indirect_branch_exec,
                                                       QEMU_PLUGIN_CB_R_REGS, (void *)insn_addr);
                if (i + 1 < num_insns) {
                    struct qemu_plugin_insn *next_insn = qemu_plugin_tb_get_insn(tb, i + 1);
                    uint8_t *next_data = (uint8_t *)qemu_plugin_insn_data(next_insn);
                    size_t next_size = qemu_plugin_insn_size(next_insn);
                    if (is_indirect_branch(next_data, next_size)) {
                        cout << "WARNING: Consecutive indirect branches are currently not handled properly" << endl;
                    }
                    qemu_plugin_register_vcpu_insn_exec_cb(next_insn, branch_skipped,
                                                           QEMU_PLUGIN_CB_R_REGS, NULL);
                }
            }
        }
    }
}

int loading_sym_failed(const char *sym, const char *backend_name) {
    cout << "Could not load `" << sym << "` function from backend " << backend_name << endl;
    cout << dlerror() << endl;
    return -4;
}

extern int qemu_plugin_install(qemu_plugin_id_t id, const qemu_info_t *info, int argc,
                               char **argv) {
    /*if (argc < 1) {
        cout << "Usage: /path/to/qemu \\" << endl;
        cout << "\t-plugin /path/to/libibresolver.so,output=\"output.csv\",backend=\"/path/to/disassembly/libbackend.so\" \\" << endl;
        cout << "\t$BINARY" << endl;
        return -1;
    }*/

    //const char *output_arg = argv[0] + sizeof("output=") - 1;

    outfile = ofstream("output.csv");
    if (outfile.fail()) {
        cout << "Could not open file output.csv" << endl;
        return -2;
    }

    bool backend_provided = argc == 1;
    void *backend_handle = RTLD_DEFAULT;
    const char *arch_supported_fn_name = "arch_supported_default_impl";
    const char *is_indirect_branch_fn_name = "is_indirect_branch_default_impl";
    const char *backend_name = BACKEND_NAME;

    if (backend_provided) {
        //const char *backend_arg = argv[1] + sizeof("backend=") - 1;   
        const char *backend_arg = argv[0];  
        backend_handle = dlopen(backend_arg, RTLD_LAZY | RTLD_DEEPBIND);    //打开后端共享库
        if (!backend_handle) {
            cout << "Could not open shared library for alternate disassembly backend" << endl;
            cout << dlerror() << endl;
            return -3;
        }
        arch_supported_fn_name = "arch_supported";
        is_indirect_branch_fn_name = "is_indirect_branch";
        backend_name = backend_arg;
    }
    cout << "Using the " << backend_name << " disassembly backend" << endl;
    arch_supported = (arch_supported_fn)dlsym(backend_handle, arch_supported_fn_name);
    if (dlerror()) {
        return loading_sym_failed(arch_supported_fn_name, backend_name);
    }
    is_indirect_branch = (is_indirect_branch_fn)dlsym(backend_handle, is_indirect_branch_fn_name);  //从动态加载库种获取is_indirect_branch_fn_name函数的地址
    if (dlerror()) {
        return loading_sym_failed(is_indirect_branch_fn_name, backend_name);
    }

    if (!arch_supported(info->target_name)) {
        cout << "Could not initialize disassembly backend for " << info->target_name << endl;
        return -5;
    }

    outfile << "callsite offset,dest offset,callsite vaddr,dest vaddr,callsite ELF,dest ELF" << endl;
    // Register a callback for each time a block is translated
    qemu_plugin_register_vcpu_tb_trans_cb(id, block_trans_handler);

    return 0;
}
