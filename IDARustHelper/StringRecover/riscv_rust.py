from .rust import proc_rust_t
from idaapi import *

# The RISC-V calling convention passes arguments in registers when possible. Up to eight integer 
# registers, a0-a7, and up to eight floating-point registers, fa0-fa7, are used for this purpose
#           a0  a1  a2  a3  a4  a5  a6  a7
rv_riscv = [10, 11, 12, 13, 14, 15, 16, 17, -1]

class riscv_rust_t(proc_rust_t):
    def __init__(self) -> None:
        super().__init__()
        self.look_forward = 5
        # hope to someone will implement ev_get_cc_regs
        self.regs.set(ARGREGS_GP_ONLY, rv_riscv, None)

    def insn_get_rptr(self, insn: insn_t) -> int:
        # la a0, unk_2672B
        if insn.itype == RISCV_la and insn.Op1.type == o_reg:
            return insn.Op1.reg
        else:
            return -1
        
    def insn_check_for_rlen(self, insn: insn_t, rlen: int) -> int:
        # li a1, 21h
        if insn.itype == RISCV_li and insn.Op1.is_reg(rlen) and insn.Op2.type == o_imm:
            return insn.Op2.value
        else:
            return -1