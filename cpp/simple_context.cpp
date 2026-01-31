#include <cstdio>
#include <optional>
#include <string>
#include <unordered_set>

#include "sleigh/error.hh"
#include "sleigh/loadimage.hh"
#include "sleigh/opcodes.hh"
#include "sleigh/sleigh.hh"
#include "sleigh/space.hh"
#include "sleigh/translate.hh"
#include "sleigh/xml.hh"

#include "simple_context.hpp"

#define ERROR_STR_SIZE 0x200
char error_str[ERROR_STR_SIZE];

using namespace ghidra;

struct PcodeOp {
    OpCode m_opcode;
    std::optional<VarnodeData> m_output;
    std::vector<VarnodeData> m_inputs;
};

class SimpleLoadImage : public LoadImage {
    uintb m_baseaddr;
    int4 m_length;
    const unsigned char *m_data;

public:
    SimpleLoadImage() : LoadImage("nofile")
    {
        m_baseaddr = 0;
        m_data = NULL;
        m_length = 0;
    }

    void setData(uintb ad, const unsigned char *ptr, int4 sz)
    {
        m_baseaddr = ad;
        m_data = ptr;
        m_length = sz;
    }

    void loadFill(uint1 *ptr, int4 size, const Address &addr)
    {
        LOG("Filling %d bytes at %lx", size, addr.getOffset());
        uintb start = addr.getOffset();
        uintb max = m_baseaddr + m_length - 1;

        //
        // When decoding an instruction, SLEIGH will attempt to pull in several
        // bytes at a time, starting at each instruction boundary.
        //
        // If the start address is outside of the defined range, bail out.
        // Otherwise, if we have some data to provide but cannot satisfy the
        // entire request, fill the remainder of the buffer with zero.
        //
        if (start > max || start < m_baseaddr) {
            throw std::out_of_range("Attempting to lift outside buffer range");
        }

        for (int4 i = 0; i < size; i++) {
            uintb curoff = start + i;
            if ((curoff < m_baseaddr) || (curoff > max)) {
                ptr[i] = 0;
                continue;
            }
            uintb diff = curoff - m_baseaddr;
            ptr[i] = m_data[(int4)diff];
        }
    }

    virtual string getArchType(void) const
    {
        return "myload";
    }
    virtual void adjustVma(long adjust)
    {
    }
};

class PcodeEmitCacher : public PcodeEmit {
public:
    std::vector<PcodeOp> m_ops;
    bool m_bb_terminating_op_emitted;

    PcodeEmitCacher() : m_bb_terminating_op_emitted(false)
    {
        m_ops.reserve(512);
    }

    // Encode P-code ops into csleigh structures and append them to the translation buffer
    void dump(const Address &addr, OpCode opc, VarnodeData *outvar, VarnodeData *invars, int4 num_invars)
    {
        LOG("Emitting pcode op %d with %d-in,%d-out varnodes from %llx",
            opc,
            num_invars,
            outvar ? 1 : 0,
            addr.getOffset());
        m_bb_terminating_op_emitted |= opc == CPUI_BRANCH || opc == CPUI_CBRANCH || opc == CPUI_BRANCHIND ||
                                       opc == CPUI_RETURN || opc == CPUI_CALL || opc == CPUI_CALLIND;

        m_ops.emplace_back();
        PcodeOp &op = m_ops.back();

        op.m_opcode = opc;
        if (outvar) {
            op.m_output.emplace(*outvar);
        }
        op.m_inputs.reserve(num_invars);
        for (int i = 0; i < num_invars; i++) {
            op.m_inputs.emplace_back(invars[i]);
        }
    }
};

struct DisassemblyInstruction {
    Address m_addr;
    uint64_t m_length;
    std::string m_mnem;
    std::string m_body;
};

class AssemblyEmitCacher : public AssemblyEmit {
public:
    DisassemblyInstruction &m_disas;

    AssemblyEmitCacher(DisassemblyInstruction &disas) : m_disas(disas)
    {
    }

    void dump(const Address &addr, const std::string &mnem, const std::string &body)
    {
        m_disas.m_addr = addr;
        m_disas.m_mnem = mnem;
        m_disas.m_body = body;
    };
};

class Disassembly {
public:
    std::vector<DisassemblyInstruction> m_instructions;

    Disassembly()
    {
        LOG("Disassembly %p created", this);
    }

    Disassembly(Disassembly &&o) noexcept : m_instructions(std::move(o.m_instructions))
    {
        LOG("Disassembly moved from %p to %p", &o, this);
    }

    ~Disassembly()
    {
        LOG("Disassembly %p released", this);
    }
};

class Translation {
public:
    std::vector<PcodeOp> m_ops;

    Translation()
    {
        LOG("Translation %p created", this);
    }

    Translation(Translation &&o) noexcept : m_ops(std::move(o.m_ops))
    {
        LOG("Translation moved from %p to %p", &o, this);
    }

    ~Translation()
    {
        LOG("Translation %p released", this);
    }
};

enum TranslateFlags {
    BB_TERMINATING = 1,
};

class SimpleContext : public ContextInternal {
    bool m_finalized;
    std::unordered_set<string> m_variables;
    Translation m_translation;
    Disassembly m_disassembly;

public:
    SimpleContext() : ContextInternal()
    {
        m_finalized = false;
    }

    virtual void registerVariable(const string &nm, int4 sbit, int4 ebit)
    {
        if (!m_finalized) {
            ContextInternal::registerVariable(nm, sbit, ebit);
            m_variables.insert(nm);
        }
    }

    void resetAllVariables()
    {
        for (const string &nm : m_variables) {
            auto val = ContextDatabase::getDefaultValue(nm);
            setVariableRegion(nm, Address(Address::m_minimal), Address(), val);
        }
    }

public:
    SimpleLoadImage m_loader;
    DocumentStorage m_document_storage;
    Document *m_document;
    Element *m_tags;
    std::unique_ptr<Sleigh> m_sleigh;

    SimpleContext(const std::string &path) : ContextInternal(), m_finalized(false)
    {
        LOG("Context %p created", this);

        // FIXME: Globals...
        AttributeId::initialize();
        ElementId::initialize();

        LOG("%p Loading slafile...", this);
        istringstream sleighfilename(path);
        m_document = m_document_storage.parseDocument(sleighfilename);
        m_tags = m_document->getRoot();
        m_document_storage.registerTag(m_tags);

        LOG("Setting up translator");
        m_sleigh.reset(new Sleigh(&m_loader, this));
        m_sleigh->initialize(m_document_storage);
        m_finalized = true;
    }

    ~SimpleContext()
    {
        LOG("Context %p released", this);
    }

    void reset(void)
    {
        m_sleigh.reset(new Sleigh(&m_loader, this));
        m_sleigh->initialize(m_document_storage);
        m_finalized = true;
    }

    Disassembly *disassemble(const char *bytes, unsigned int num_bytes, uint64_t address, unsigned int max_instructions)
    {
        LOG("%p Disassembling bytes=%p, num_bytes=%d, address=%lx", this, bytes, num_bytes, address);
        Disassembly *disassembly = &m_disassembly;
        int num_instructions = 0;
        uint32_t offset = 0;

        m_sleigh->fastReset();
        m_loader.setData(address, (const unsigned char *)bytes, num_bytes);
        disassembly->m_instructions.reserve(10);

        while ((offset < num_bytes) && (!max_instructions || (num_instructions < max_instructions))) {
            Address addr(m_sleigh->getDefaultCodeSpace(), address + offset);

            disassembly->m_instructions.emplace_back();
            DisassemblyInstruction &ins = disassembly->m_instructions.back();

            AssemblyEmitCacher asm_cache(ins);

            // Disassemble the next instruction. If an error occurs after successful disassembly of at least one
            // instruction, suppress the error and return the successful disassembly. If the caller attempts
            // disassembly again at the position where the error occurred, then propagate the error.
            try {
                ins.m_length = m_sleigh->printAssembly(asm_cache, addr);
            } catch (BadDataError &err) {
                if (offset) {
                    disassembly->m_instructions.resize(num_instructions);
                    break;
                }
                throw err;
            } catch (std::out_of_range &err) {
                if (offset) {
                    disassembly->m_instructions.resize(num_instructions);
                    break;
                }
                throw err;
            }

            num_instructions += 1;
            offset += ins.m_length;
        }

        return disassembly;
    }

    Translation *translate(const char *bytes,
                           unsigned int num_bytes,
                           uint64_t base_address,
                           unsigned int max_instructions,
                           uint32_t flags)
    {
        LOG("%p Translating bytes=%p, num_bytes=%d, base_address=0x%llx, max_instructions=%d flags=0x%x",
            this,
            bytes,
            num_bytes,
            base_address,
            max_instructions,
            flags);
        PcodeEmitCacher pcode_cache;
        uint32_t offset = 0;
        Translation *translation = &m_translation;
        translation->m_ops.clear();
        m_sleigh->fastReset();
        m_loader.setData(base_address, (const unsigned char *)bytes, num_bytes);

        int num_instructions = 0;
        while ((offset < num_bytes) && (!max_instructions || (num_instructions < max_instructions))) {
            Address addr(m_sleigh->getDefaultCodeSpace(), base_address + offset);
            LOG("Lifting at 0x%llx+0x%x=0x%llx", base_address, offset, base_address + offset);

            int imark_idx = pcode_cache.m_ops.size();
            pcode_cache.m_ops.emplace_back();

            // Translate the next instruction. If an error occurs after successful translation of at least one
            // instruction, suppress the error and return the successful translation. If the caller attempts
            // translation again at the position where the error occurred, then propagate the error.
            uint32_t num_bytes_decoded = 0;
            try {
                num_bytes_decoded = m_sleigh->oneInstruction(pcode_cache, addr);
            } catch (BadDataError &err) {
                if (offset) {
                    pcode_cache.m_ops.resize(imark_idx);
                    break;
                }
                throw err;
            } catch (UnimplError &err) {
                if (offset) {
                    pcode_cache.m_ops.resize(imark_idx);
                    break;
                }
                throw err;
            } catch (std::out_of_range &err) {
                if (offset) {
                    pcode_cache.m_ops.resize(imark_idx);
                    break;
                }
                throw err;
            }

            PcodeOp &imark_op = pcode_cache.m_ops[imark_idx];
            imark_op.m_opcode = OpCode::CPUI_IMARK;

            // Add varnode to imark op for every decoded instruction in this translation
            for (int sum = 0; sum < num_bytes_decoded;) {
                imark_op.m_inputs.emplace_back();
                VarnodeData &imark_vn = imark_op.m_inputs.back();
                imark_vn.space = addr.getSpace();
                imark_vn.offset = addr.getOffset() + sum;
                imark_vn.size = m_sleigh->instructionLength(addr);

                sum += imark_vn.size;
                num_instructions++;
            }

            if ((flags & TranslateFlags::BB_TERMINATING) && pcode_cache.m_bb_terminating_op_emitted) {
                LOG("Reached end of block");
                break;
            }

            offset += num_bytes_decoded;
        }

        translation->m_ops = std::move(pcode_cache.m_ops);
        return translation;
    }
};


PContext create_context(const char *path)
{
    return new SimpleContext(path);
}

void destroy_context(PContext ctx)
{
    if (ctx != nullptr) {
        delete static_cast<SimpleContext *>(ctx);
    }
}

void reset_context(PContext ctx)
{
    SimpleContext *ctx_rspcode = static_cast<SimpleContext *>(ctx);
    ctx_rspcode->reset();
}

void context_set_variable_default(PContext ctx, const char *name, ghidra::uintm val)
{
    SimpleContext *ctx_rspcode = static_cast<SimpleContext *>(ctx);
    ctx_rspcode->setVariableDefault(name, val);
}

PDisassembly
disassemble(PContext ctx, const char *bytes, unsigned int num_bytes, uint64_t address, unsigned int max_instructions)
{
    SimpleContext *ctx_rspcode = static_cast<SimpleContext *>(ctx);
    LOG("Disassembling %p", ctx);
    try {
        return static_cast<PDisassembly>(ctx_rspcode->disassemble(bytes, num_bytes, address, max_instructions));
    } catch (BadDataError &err) {
        LOG("BadDataError: %s", err.what());
        return nullptr;
    } catch (UnimplError &err) {
        LOG("UnimplError: %s", err.what());
        return nullptr;
    } catch (DecoderError &err) {
        LOG("DecoderError: %s", err.what());
        return nullptr;
    }
}

size_t get_disassembly_insn_count(PDisassembly disas)
{
    Disassembly *real_disas = static_cast<Disassembly *>(disas);
    return real_disas->m_instructions.size();
}

PDisassemblyInstruction get_disassembly_insn(PDisassembly disas, size_t index)
{
    Disassembly *real_disas = static_cast<Disassembly *>(disas);
    if (index >= real_disas->m_instructions.size()) {
        return nullptr;
    }
    return &real_disas->m_instructions[index];
}

void get_insn_address(PDisassemblyInstruction insn, PAddress *addr)
{
    Address *g_addr = &static_cast<DisassemblyInstruction *>(insn)->m_addr;
    addr->offset = g_addr->getOffset();
    addr->space.name = g_addr->getSpace()->getName().c_str();
    addr->space.type = g_addr->getSpace()->getType();
}

size_t get_insn_length(PDisassemblyInstruction insn)
{
    return static_cast<DisassemblyInstruction *>(insn)->m_length;
}

const char *get_insn_mnem(PDisassemblyInstruction insn)
{
    return static_cast<DisassemblyInstruction *>(insn)->m_mnem.c_str();
}

const char *get_insn_body(PDisassemblyInstruction insn)
{
    return static_cast<DisassemblyInstruction *>(insn)->m_body.c_str();
}


PTranslation translate(PContext ctx,
                       const char *bytes,
                       unsigned int num_bytes,
                       uint64_t base_address,
                       unsigned int max_instructions,
                       uint32_t flags)
{
    LOG("Translating %p", ctx);
    SimpleContext *ctx_rspcode = static_cast<SimpleContext *>(ctx);
    try {
        return ctx_rspcode->translate(bytes, num_bytes, base_address, max_instructions, flags);
    } catch (BadDataError &err) {
        snprintf(error_str, ERROR_STR_SIZE, "BadDataError: %s", err.explain.c_str());
        return nullptr;
    } catch (UnimplError &err) {
        snprintf(error_str, ERROR_STR_SIZE, "UnimplError: %s", err.explain.c_str());
        return nullptr;
    } catch (DecoderError &err) {
        snprintf(error_str, ERROR_STR_SIZE, "DecoderError: %s", err.explain.c_str());
        return nullptr;
    } catch (std::bad_alloc &err) {
        snprintf(error_str, ERROR_STR_SIZE, "std::bad_alloc: %s", err.what());
        return nullptr;
    } catch (std::out_of_range &err) {
        snprintf(error_str, ERROR_STR_SIZE, "std::out_of_range: %s", err.what());
        return nullptr;
    } catch (std::exception &err) {
        snprintf(error_str, ERROR_STR_SIZE, "std::exception: %s", err.what());
        return nullptr;
    }
}

size_t get_translation_op_count(PTranslation trans)
{
    return static_cast<Translation *>(trans)->m_ops.size();
}

PPcodeOp get_translation_op(PTranslation trans, size_t index)
{
    Translation *real_trans = static_cast<Translation *>(trans);
    if (index >= real_trans->m_ops.size()) {
        return nullptr;
    }
    return &real_trans->m_ops[index];
}

uint32_t get_translation_op_opcode(PPcodeOp op)
{
    PcodeOp *real_op = static_cast<PcodeOp *>(op);
    return real_op->m_opcode;
}

static std::string tmp_reg_name;

static const char *get_register_name(VarnodeData *g_var)
{
    if (g_var->space->getType() != IPTR_PROCESSOR) {
        return nullptr;
    }
    tmp_reg_name = g_var->space->getTrans()->getRegisterName(g_var->space, g_var->offset, g_var->size);
    return tmp_reg_name.c_str();
}

bool get_translation_op_output(PPcodeOp op, PVarnodeData *var)
{
    PcodeOp *real_op = static_cast<PcodeOp *>(op);
    if (!real_op->m_output) {
        return false;
    }
    VarnodeData *g_var = &real_op->m_output.value();
    var->space.name = g_var->space->getName().c_str();
    var->space.type = g_var->space->getType();
    var->offset = g_var->offset;
    var->size = g_var->size;
    var->reg_name = get_register_name(g_var);
    return true;
}

size_t get_translation_op_input_count(PPcodeOp op)
{
    return static_cast<PcodeOp *>(op)->m_inputs.size();
}

bool get_translation_op_input(PPcodeOp op, size_t index, PVarnodeData *var)
{
    PcodeOp *real_op = static_cast<PcodeOp *>(op);
    if (index >= real_op->m_inputs.size()) {
        return false;
    }
    VarnodeData *g_var = &real_op->m_inputs[index];
    var->space.name = g_var->space->getName().c_str();
    var->space.type = g_var->space->getType();
    var->offset = g_var->offset;
    var->size = g_var->size;
    var->reg_name = get_register_name(g_var);
    return true;
}
