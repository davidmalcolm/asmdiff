"""
Script for comparing output of "objdump -d"
"""
from collections import OrderedDict
import re
import sys

class Instruction:
    def __init__(self, offset, bytes_, disasm):
        self.offset = HexInt(offset)
        self.bytes_ = bytes_
        self.disasm = disasm

    def __repr__(self):
        return ('Instruction(%r, %r, %r)'
                % (self.offset, self.bytes_, self.disasm))

class Function:
    def __init__(self, offset, name):
        self.offset = HexInt(offset)
        self.name = name
        self.instrs = []

class Section:
    def __init__(self, name):
        self.name = name

hexgrp = r'([0-9a-f]+)'
opt_ws = '\s*'

def from_hex(str_):
    return int(str_, 16)

class HexInt(int):
    """
    An int that prints itself in hexadecimal
    """
    def __str__(self):
        return '0x%x' % self

class AsmFile:
    def __init__(self):
        self._cur_section = None
        self._cur_function = None
        self.sections = OrderedDict()
        self.functions = OrderedDict()

class ObjDump(AsmFile):
    """
    Parser for output from objdump -d
    """
    def __init__(self, f, debug=0):
        AsmFile.__init__(self)
        self.debug = debug

        self.objpath = None
        self.fileformat = None

        for line in f:
            if debug:
                print(repr(line))

            # Ignore blank lines:
            if line == '\n':
                continue

            m = re.match('^(.+):\s+file format (.+)$', line)
            if m:
                self.objpath = m.group(1)
                self.fileformat = m.group(2)
                continue

            m = re.match('^Disassembly of section (.+):$', line)
            if m:
                self._on_section(m.group(1))
                continue

            m = re.match('^' + hexgrp + ' <(.+)>:$', line)
            if m:
                self._on_function(from_hex(m.group(1)), m.group(2))
                continue

            if self._cur_function:
                m = re.match('^' + opt_ws + hexgrp + ':\t' + '([0-9a-f ]+)\t(.+)$', line)
                if m:
                    self._on_instruction(from_hex(m.group(1)),
                                         [from_hex(str_) for str_ in m.group(2).split()],
                                         m.group(3))
                    continue

            if self._cur_function:
                m = re.match('^' + opt_ws + hexgrp + ':\t' + '([0-9a-f ]+)$', line)
                if m:
                    self._on_instruction(from_hex(m.group(1)),
                                         [from_hex(str_) for str_ in m.group(2).split()],
                                         '')
                    continue

            raise ValueError('Unhandled line: %r' % line)

    def _on_section(self, name):
        if self.debug:
            print('SECTION: %s' % name)
        self._cur_section = Section(name)
        self.sections[name] = self._cur_section

    def _on_function(self, offset, name):
        if self.debug:
            print('FUNCTION:0x%x %s' % (offset, name))
        self._cur_function = Function(offset, name)
        self.functions[name] = self._cur_function

    def _on_instruction(self, offset, hexdump, disasm):
        if self.debug:
            print('INSTRUCTION:0x%x %r %r' % (offset, hexdump, disasm))
        # Fixup jump offsets to refer to "THIS_FN" (to minimize changes due
        # to function renaming)
        m = re.match(r'.*\s([0-9a-f]+ \<.+\+0x[0-9a-f]+\>)', disasm)
        if m:
            m2 = re.match(r'[0-9a-f]+ \<(.+)\+(0x[0-9a-f]+)\>',
                          m.group(1))
            if m2.group(1) == self._cur_function.name:
                disasm = disasm[:m.start(1)] + 'THIS_FN+' + m2.group(2) + disasm[m.end(1):]
        instr = Instruction(offset, hexdump, disasm)
        self._cur_function.instrs.append(instr)

def fn_equal(old, new):
    if len(old.instrs) != len(new.instrs):
        return False
    return all(oldinstr.disasm == newinstr.disasm
               for oldinstr, newinstr in zip(old.instrs, new.instrs))

def fn_diff(old, new, out):
    def handle_minor_changes():
        if old.name != new.name:
            out.writeln('  (renamed to %s)' % new.name)
        if old.offset != new.offset:
            out.writeln('  (moved offset within section from %s to %s)' % (old.offset, new.offset))

    if fn_equal(old, new):
        out.writeln('Unchanged function: %s' % old.name)
        handle_minor_changes()
        return

    out.writeln('Changed function: %s' % old.name)
    handle_minor_changes()

    with out.indent():
        for oldinstr, newinstr in zip(old.instrs, new.instrs):
            if oldinstr.disasm == newinstr.disasm:
                out.writeln('FN+%04s: %s' % (HexInt(oldinstr.offset - old.offset), oldinstr.disasm))
            else:
                out.writeln('FN+%04s: Old: %s' % (HexInt(oldinstr.offset - old.offset), oldinstr.disasm))
                out.writeln('       : New: %s' % (newinstr.disasm, ))

class Peers:
    """
    Match up peers between two sets of items, old and new
    """
    def __init__(self, old, new):
        self.old = old
        self.new = new
        self.old_to_new = {}
        self.new_to_old = {}
        self.gone = []
        self.appeared = []
        for olditem in old:
            newitem = self._lookup(olditem)
            if newitem:
                self.old_to_new[olditem] = newitem
                self.new_to_old[newitem] = olditem
            else:
                self.gone.append(olditem)
        for newitem in new:
            if newitem not in self.new_to_old:
                self.appeared.append(newitem)

    def _lookup(self, olditem):
        raise NotImplementedError

class FunctionPeers(Peers):
    """
    Match up peer function names
    """
    def _lookup(self, olditem):
        if olditem in self.new:
            return olditem
        # Find things that were moved to anonymous namespaces:
        add_anon = '(anonymous namespace)::' + olditem
        if add_anon in self.new:
            return add_anon

def asm_diff(old, new, out):
    out.writeln('Old: %s' % old.objpath)
    out.writeln('New: %s' % new.objpath)
    peers = FunctionPeers(old.functions.keys(), new.functions.keys())
    with out.indent():
        for gone in peers.gone:
            out.writeln('Function removed: %s' % gone)
        for appeared in peers.appeared:
            out.writeln('Function added: %s' % appeared)
        for oldname, newname in peers.old_to_new.iteritems():
            oldfn = old.functions[oldname]
            newfn = new.functions[newname]
            fn_diff(oldfn, newfn, out)

class Output:
    def __init__(self):
        self._indent = 0

    def writeln(self, str_):
        print('%s%s' % (self._indent * '  ', str_))

    def indent(self):
        class IndentCM:
            # context manager for indenting/outdenting the output
            def __init__(self, output):
                self.output = output

            def __enter__(self):
                self.output._indent += 1

            def __exit__(self, exc_type, exc_value, traceback):
                self.output._indent -= 1
        return IndentCM(self)

def read_objdump(path):
    with open(path) as f:
        return ObjDump(f)

if __name__ == '__main__':
    old = read_objdump(sys.argv[1])
    new = read_objdump(sys.argv[2])
    asm_diff(old, new, Output())
