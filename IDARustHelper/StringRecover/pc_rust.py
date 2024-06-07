from .rust import proc_rust_t
from idaapi import *

class pc_rust_t(proc_rust_t):
    def __init__(self) -> None:
        super().__init__()

    # lea rax, aImagine
    def insn_get_rptr(self, insn: insn_t) -> int:
        if insn.itype == NN_lea and insn.Op1.type == o_reg:
            return insn.Op1.reg
        else:
            return -1
        
    # mov esi, 1Ch         ; .len (_str.length)
    def insn_check_for_rlen(self, insn: insn_t, rlen: int) -> int:
        if insn.itype == NN_mov and insn.Op1.is_reg(rlen) and insn.Op2.type == o_imm:
            return insn.Op2.value
        else:
            return -1
        
    # mov [rsp+238h+var_60.length], 7
    def is_rlen_stk_insn(self, insn: insn_t, rbase:int, stkoff: int) -> bool:
        return insn.itype == NN_mov and insn.Op1.type == o_displ and insn.Op1.reg == rbase and insn.Op1.addr == stkoff + self.bitness // 8 and insn.Op2.type == o_imm
    
    def get_strlen(self, insn_ea: int, strlit_ea: int) -> int:
        strlen = super().get_strlen(insn_ea, strlit_ea)
        if strlen != -1:
            return strlen
        
        if self.is64:
            insn = insn_t()
            if decode_insn(insn, insn_ea) == 0:
                return -1
            rptr = self.insn_get_rptr(insn)
            if rptr != -1:
                for _ in range(self.look_forward):
                    next_ea = insn.ea + insn.size
                    if decode_insn(insn, next_ea) == 0:
                        return -1
                    if insn.itype == NN_jmp and insn.Op1.type == o_near:
                        if decode_insn(insn, insn.Op1.addr) == 0:
                            return -1
                    # lea rax, aImagine
                    # mov [rsp+238h+var_60.data_ptr], rax
                    # ......
                    # mov [rsp+238h+var_60.length], 7
                    # or another situation like:
                    # lea rax, unk_9E64D
                    # mov [rbx+580h], rax
                    # ......
                    # mov qword ptr [rbx+588h], 6Dh ; 'm'
                    if insn.itype == NN_mov and insn.Op1.type == o_displ and insn.Op2.is_reg(rptr):
                        stkoff = insn.Op1.addr
                        rbase = insn.Op1.reg
                        for _ in range(self.look_forward):
                            next_ea += insn.size
                            if decode_insn(insn, next_ea) > 0:
                                if self.is_rlen_stk_insn(insn, rbase, stkoff):
                                    return insn.Op2.value
                            else:
                                return -1
                        return -1
                    elif insn.itype == NN_push and insn.Op1.type == o_imm:
                        return insn.Op1.value
                    
                    
            # .text:000000014009E009                 lea     rdx, unk_1401D0BF5
            # .text:000000014009E010                 jmp     loc_14009E199
            # .text:000000014009E015 ; ---------------------------------------------------------------------------
            # .text:000000014009E015 loc_14009E015:
            # .text:000000014009E015                 mov     rcx, [rsi+20h]  ; jumptable 000000014009DEBA case 14
            # .text:000000014009E019                 mov     rax, [rsi+28h]
            # .text:000000014009E01D                 mov     rax, [rax+18h]
            # .text:000000014009E021                 lea     rdx, unk_1401D0BEC
            # .text:000000014009E028                 mov     r8d, 9
            # .text:000000014009E02E                 jmp     loc_14009E229

            # .text:000000000001DF0E                 lea     rax, unk_40AE0  ; jumptable 000000000001DCEB case 33
            # .text:000000000001DF15                 mov     ecx, 10h
            # .text:000000000001DF1A                 jmp     short loc_1DF7C
        return -1
    