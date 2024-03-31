from idaapi import *
import idautils
from rust_demangler import demangle

class IDARustDemangler():
    """
    IDARustDemangler is a tool that demangles and normalizes symbols for use with the IDA disassembler.
    It replaces or modifies special characters to make them compatible with IDA's syntax, 
    making binary analysis faster and more efficient.
    """

    def __init__(self, debug=False):
        self.debug = debug
        self.num_resolved = 0
        self.hash_prefix = "17h"
        self.delimiters = "><"
        self.badchars = "*,'`" + self.delimiters
        self.queue = {}
        self.resolved = {}

    def add(self, address: int, symbol: str) -> None:
        # Must add support for non legacy symbols

        if symbol in self.queue.values():
            return

        # If the hash is present
        if symbol.lstrip("_").startswith("Z") and self.hash_prefix in symbol:
            hash = symbol.split(self.hash_prefix)[-1].rstrip("E")

            # If the hash length is not 16 skip as it is not a valid rust legacy symbol
            if len(hash) != 16:
                return

            self.queue[address, hash] = symbol
        else:
            # If the hash is not present
            if '::' in symbol:
                self.queue[address, ""] = symbol

    def resolve(self):
        resolved_symbols = []
        for symbol in self.queue.values():
            try:
                if symbol != demangle(symbol):
                    resolved_symbols.append(demangle(symbol))
            except:
                resolved_symbols.append(symbol)
        self.resolved = zip(self.queue.keys(), resolved_symbols)

    def apply(self):
        # for each symbol resolved normalize it and apply it to the IDA db
        for (address, hash), symbol in self.resolved:
            set_func_cmt(get_func(address), symbol, 1)
            normalized = self.ida_normalize(symbol)

            # If normalization succeded and all the character in the normalized
            # symbol are valid set the name in IDA
            if any([badchar in normalized for badchar in self.badchars]) and self.debug:
                print(
                    f"[ERROR] {address:#016x} -> sym:'{symbol}', hash: '{hash}', normalized: '{normalized}'")
                continue

            if self.debug:
                print(
                    f"[*] {address:#016x} -> sym:'{symbol}', hash: '{hash}', normalized: '{normalized}'")

            # set the name and add the hash at the end
            # print(f"[*] {address:#x} -> {normalized + str(len(hash)) + hash}")
            if hash == "":
                set_name(address, normalized)
            else:
                set_name(address, normalized + str(len(hash)) + hash)
            self.num_resolved += 1

    def ida_normalize(self, name: str) -> str:
        """
        This function tries to normalize sybmols to be accepted by IDA
        """

        # Replace bad characters with accepted ones
        # unfortunately there is no way known to me
        # to insert these chars into IDA symbol names

        name = name.replace(" ", "_")
        name = name.replace(",", "_")
        name = name.replace("{", "<")
        name = name.replace("}", ">")
        name = name.replace("'","_")
        name = name.replace("`","_")
        name = name.replace("-","_")
        name = name.replace("=","_")
        name = name.replace("\\","_")
        name = name.replace(";","_")
        name = name.replace("+","_")
        name = name.replace("!","_")

        i = 0
        output = "_ZN"

        while i < len(name):
            if name[i] == "<":
                # 'I' corresponds to '<'
                output += "I"
                i += 1
            elif name[i] == ">":
                # 'E' corresponds to '>'
                output += "E"
                i += 1
            elif name[i] == "*":
                # 'P' corresponds to pointer-type word
                output += "P"
                i += 1
            else:

                # if it the `word` starts with "::" skip it
                # as IDA automatically adds it
                if name[i:i+2] == "::":
                    i += 2

                # this should find the closest delimiter to
                # recognize the entire word

                idxs = []

                for special_char in self.delimiters:
                    tmp_idx = name[i+1:].find(special_char)

                    if tmp_idx != -1:
                        idxs.append(tmp_idx)

                if len(idxs) >= 1:
                    idx = min(idxs)
                    word = name[i:i+idx + 1]
                else:
                    word = name[i:]

                if len(word) > 0:
                    if "*" in word:
                        # if '*' is present it means it is a pointer just have
                        # to a number of 'P' at the start of the word
                        # corresponding to the number of '*'
                        output += "P" * word.count("*")
                        i += word.count("*")
                        word = word.replace("*", "")

                    output += str(len(word)) + word

                i += len(word)

        output += "E"
        return output
    
    def run(self):
        print("Demangler started!")
        for address in idautils.Functions():
            self.add(address, get_func_name(address))

        self.resolve()
        self.apply()
        print(f"Demangled {self.num_resolved} symbols")