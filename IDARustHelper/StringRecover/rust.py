from idaapi import *
import idc

class proc_rust_t:
    '''encapsulate the basic methods and data used during processing the xref which in code segment'''
    def __init__(self) -> None:
        self.look_forward = 5
        self.look_backward = 5
        self.is64 = inf_get_app_bitness() == 64
        self.bitness = inf_get_app_bitness()
        # is 32bit rust binary still use fastcall?
        self.regs = callregs_t(CM_CC_FASTCALL)

    def get_strlen(self, insn_ea: int, strlit_ea: int) -> int:
        '''
        check the neighbor instructions of INSN_EA to find the strlit length
        @param: insn_ea    insn EA which loads of strlit address
        @param: strlit_ea  strlit EA with dr_O to INSN_EA
        @return: -1 if not successful
        
        The default implementation uses the commont patterns for register-based ABI:
        1: load _str.ptr to RPTR register      <- INSN_EA
            may be several alien insns\n
            load _str.length to RLEN register\n
        2: load _str.length to RLEN register\n
            may be several alien insns\n
            load _str.ptr to RPTR register      <- INSN_EA
        '''
        insn = insn_t()
        if not decode_insn(insn, insn_ea):
            return -1
        rptr = self.insn_get_rptr(insn)
        if rptr == -1:
            return -1
        rlen = self.get_rlen_by_rptr(rptr)
        if rlen != -1:
            # pattern 1
            ea = insn.ea + insn.size
            for _ in range(self.look_forward):
                if self.break_scan(ea):
                    break
                if not decode_insn(insn, ea):
                    break
                
                strlen = self.insn_check_for_rlen(insn, rlen)
                if strlen != -1:
                    return strlen
                ea += insn.size

            # pattern 2
            ea = insn.ea
            for _ in range(self.look_backward):
                if decode_prev_insn(insn, ea) != BADADDR:
                    strlen = self.insn_check_for_rlen(insn, rlen)
                    if strlen != -1:
                        return strlen
                ea = insn.ea
                if self.break_scan(ea):
                    break

        return -1


    def insn_get_rptr(self, insn: insn_t) -> int:
        '''callbacks for default get_strlen implementation'''
        return -1
    
    def insn_check_for_rlen(self, insn: insn_t, rlen: int) -> int:
        return -1

    # helper
    def findreg(self, regs, r) -> int:
        for i in range(len(regs.gpregs)):
            if regs.gpregs[i] == r:
                return i
        return -1

    def get_rlen_by_rptr(self, rptr: int) -> int:
        '''
        _str { data_ptr; length } is placed to two sequential callregs
        @return: register for _str.length or -1
        '''
        rlen = -1
        rptr_ind = self.findreg(self.regs, rptr)
        if rptr_ind != -1 and rptr_ind < len(self.regs.gpregs) - 1:
            rlen = self.regs.gpregs[rptr_ind + 1]
        return rlen
    
    def break_scan(self, ea: int) -> bool:
        # is jump or call insn?
        if get_first_fcref_from(ea) != BADADDR:
            return True
        
        # is return insn?
        insn = insn_t()
        return decode_insn(insn, ea) > 0 and is_ret_insn(insn, False)

rust_strlit_names = ["__const", ".rodata", ".rdata"]

class rust_ctx_t:
    '''handle the whole process of rust string recovery'''
    def __init__(self, debug=False) -> None:
        self.bitness = inf_get_app_bitness()
        ph_id = ph_get_id()
        if ph_id == PLFM_386:
            from .pc_rust import pc_rust_t
            self.mod = pc_rust_t()
        elif ph_id == PLFM_ARM:
            from .arm_rust import arm_rust_t
            self.mod = arm_rust_t()
        elif ph_id == PLFM_RISCV:
            from .riscv_rust import riscv_rust_t
            self.mod = riscv_rust_t()
        else:
            raise Exception("Unsupported platform")
        self.debug = debug
        
    def get_strlen(self, ea_ptr: int) -> int:
        if self.bitness == 32:
            return get_dword(ea_ptr + 4)
        else:
            return get_qword(ea_ptr + 8)

    def get_mod_strlen(self, insn_ea: int, strlit_ea: int) -> int:
        return self.mod.get_strlen(insn_ea, strlit_ea)

    def make_str(self, ea_ptr: int) -> bool:
        name = get_name(get_first_dref_from(ea_ptr))
        if name == None:
            return False
        if self.bitness == 32:
            flag = idc.create_struct(ea_ptr, 8, "str")
        else:
            flag = idc.create_struct(ea_ptr, 16, "str")
        if flag:
            return set_name(ea_ptr, 'str_' + name, SN_FORCE)
        else:
            return False

        # appbytes = self.bitness // 8
        # ea_len = ea_ptr + appbytes
        # sz_len = appbytes
        # # TODO: create str struct in more lenient conditions
        # if is_head(get_flags(ea_len)) and get_item_size(ea_len) != sz_len:
        #     if self.bitness == 32:
        #         # return create_dword(ea_len, sz_len, True)
        #         return idc.create_struct(ea_ptr, 8, "str")
        #     else:
        #         # return create_qword(ea_len, sz_len, True)
        #         return idc.create_struct(ea_ptr, 16, "str")
        # else:
        #     return False

    def perform_final_strlit_analysis(self):
        '''
        Try to find the strlits and create the missed strings.
        RUST does not use string pool, string literal is an ordinary constant 
        and can be alternated with the other constants 
        '''
        print("Creating Rust-specific string literals")
        qty = get_segm_qty()
        for i in range(qty):
            seg = getnseg(i)
            sname:str = get_segm_name(seg)
            if sname != -1:
                for pn in rust_strlit_names:
                    if sname.endswith(pn):
                        if not self.process_strlit_range(seg):
                            break
        print("Rust-specific string literals created")

    def process_strlit_range(self, r: range_t) -> bool:
        '''
        create strlits in range identified by xref:
        * get EA with xref
        * check for strlit
        * adjust length using next xref
        * create strlit
        '''
        if self.debug:
            print("RUST: process_strlit_range %#x..%#x\n" % (r.start_ea, r.end_ea))
        minbytes = self.bitness // 8
        ea = r.start_ea

        while ea < r.end_ea:
            length = get_max_strlit_length(ea, STRTYPE_C, ALOPT_IGNHEADS | ALOPT_IGNPRINT | ALOPT_IGNCLT)
            if length < minbytes:   # FIXME
                # let skip small strlit
                ea = next_that(ea, r.end_ea, has_xref)
                continue
            # Initially dividing strings by xrefs
            end = next_that(ea, ea + length, has_xref)
            if end != BADADDR:
                length = end - ea
            length = self.check_for_strlit(ea, length)
            ea += length
        
        return True

    def check_for_strlit(self, ea: int, length: int) -> int:
        '''
        Create strlit if it has meaning.
        We should be completely sure to create a strlit
        otherwise we produce a mess:
        * try to check the xref'ed places and may be to adjust the length
        * do not forget about the classic C-like 0-terminated strings
        '''
        if self.debug:
            print("RUST: check_for_strlit %#x..%#x\n" % (ea, ea+length))

        # Usually the difference between adjusted length and input length should less then 3.
        # Turned out that find the false descriptor for C-like string is easy.
        max_len_delta = 3
        adjlen = 0      # adjusted length
        trust_counter = 0

        # at first check data refs as the more reliable way (.data.rel.ro)
        drefs = []
        xb = xrefblk_t()        # use xrefblk_t to get more info about xref
        ok = xb.first_to(ea, XREF_DATA)
        while ok:
            if xb.type != dr_O:
                ok = xb.next_to()
                continue
            frm = xb.frm
            F = get_flags(frm)
            if is_data(F):
                detected_len = self.get_strlen(frm)
                if detected_len > length:   # false alarm, must be string length at least
                    ok = xb.next_to()
                    continue
                if adjlen == 0:
                    adjlen = detected_len
                elif adjlen != detected_len:
                    return length   # every ref must describe the same strlit
                trust_counter += 1
                drefs.append(frm)
            ok = xb.next_to()

        if adjlen == 0:
            # check code refs
            ok = xb.first_to(ea, XREF_DATA)
            while ok:
                if xb.type != dr_O:
                    ok = xb.next_to()
                    continue
                frm = xb.frm
                F = get_flags(frm)
                if is_code(F):
                    detected_len = self.get_mod_strlen(frm, ea)
                    if detected_len != -1:
                        if adjlen == 0:
                            adjlen = detected_len
                        elif adjlen != detected_len:
                            return length
                        trust_counter += 1
                ok = xb.next_to()
                
        if adjlen != 0 and adjlen <= length and (trust_counter > 1 or (length - adjlen) < max_len_delta):
            if self.debug:
                print("RUST: strlit %#x..%#x\n" % (ea, ea+adjlen))
            length = adjlen
            F = get_flags(ea)
            if is_tail(F):  # preserve the strlit item head to decrease the mess
                head = get_item_head(ea)
                if is_strlit(get_flags(head)):
                    del_items(head, DELIT_SIMPLE, ea-head)
                    create_strlit(head, ea-head, STRTYPE_C)
            itemsz = get_item_size(ea)
            del_items(ea, DELIT_SIMPLE, length)
            create_strlit(ea, length, STRTYPE_C)
            if is_strlit(F):
                if length < itemsz - 1:
                    create_strlit(ea + length, itemsz - length, STRTYPE_C)
                elif length == itemsz - 1:
                    create_byte(ea + length, 1, True)
            
            for dea in drefs:
                self.make_str(dea)

        return length
                    
    