from .rust import proc_rust_t
from idaapi import *

# Rust ABI need to be investigated,
# assume callregs: X0, X1, X2, X3, X4, X5, X6, X7, X8, X9, X10, X11, X12, X13, X14, X15, -1
rv_arm = [129, 130, 131, 132, 133, 134, 135, 136, 137, 138, 139, 140, 141, 142, 143, 144, -1]

class arm_rust_t(proc_rust_t):
    def __init__(self) -> None:
        super().__init__()
        self.look_forward = 8
        if self.is64:
            self.regs.set(ARGREGS_GP_ONLY, rv_arm, None)    # How to pass const int * parm...?

    def insn_get_rptr(self, insn: insn_t) -> int:
        if self.is64:
            # ADRL X1, aSel
            # ADRP X9, #unk_34C56@PAGE
            if (insn.itype == ARM_adrl or insn.itype == ARM_adrp) and insn.Op1.type == o_reg:
                return insn.Op1.reg
            else:
                return -1
        else:
            # LDR R0, =(unk_28E30 - 0x32D0)
            if insn.itype == ARM_ldr and insn.Op1.type == o_reg:
                return insn.Op1.reg
            else:
                return -1

    def insn_check_for_rlen(self, insn: insn_t, rlen: int) -> int:
        # MOV W2, #0x20
        # MOVS R1, #0xC
        if insn.itype == ARM_mov and insn.Op1.is_reg(rlen) and insn.Op2.type == o_imm:
            return insn.Op2.value
        else:
            return -1
    