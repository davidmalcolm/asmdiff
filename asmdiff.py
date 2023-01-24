#!/usr/bin/env python
#   Copyright 2013, 2015, 2023 David Malcolm <dmalcolm@redhat.com>
#   Copyright 2013, 2015, 2023 Red Hat, Inc.
#
#   This library is free software; you can redistribute it and/or
#   modify it under the terms of the GNU Lesser General Public
#   License as published by the Free Software Foundation; either
#   version 2.1 of the License, or (at your option) any later version.
#
#   This library is distributed in the hope that it will be useful,
#   but WITHOUT ANY WARRANTY; without even the implied warranty of
#   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
#   Lesser General Public License for more details.
#
#   You should have received a copy of the GNU Lesser General Public
#   License along with this library; if not, write to the Free Software
#   Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301
#   USA
"""
Script for comparing output of "objdump -d"
"""
from collections import OrderedDict
from subprocess import Popen, PIPE
import re
import sys

class Demangler:
    def __init__(self):
        self.p = Popen(['c++filt'], stdin=PIPE, stdout=PIPE, text=True)

    def __del__(self):
        self.p.terminate()
        outs, errs = self.p.communicate()

    def demangle(self, name):
        self.p.stdin.write('%s\n' % name)
        self.p.stdin.flush()
        return self.p.stdout.readline().rstrip()

class Instruction:
    def __init__(self, offset, bytes_, disasm):
        self.offset = HexInt(offset)
        self.bytes_ = bytes_
        self.disasm = disasm

    def __repr__(self):
        return ('Instruction(%s, %r, %r)'
                % (self.offset, self.bytes_, self.disasm))

    def __eq__(self, other):
        if self.offset != other.offset:
            return False
        if self.bytes_ != other.bytes_:
            return False
        if self.disasm != other.disasm:
            return False
        return True

class Scope(dict):
    """
    Scope/namespace for matching C++ names
    """
    def __init__(self, name):
        self.name = name

class Function:
    def __init__(self, section, offset, rawname, demangled, leafname):
        self.section = section
        self.offset = HexInt(offset)
        self.rawname = rawname
        self.demangled = demangled
        # The "leafname" is the name within the innermost scope
        self.leafname = leafname
        self.instrs = []
        self.padding = []
        self.size = 0

    def __repr__(self):
        return 'Function(%r)' % self.demangled

    def __hash__(self):
        return hash(self.rawname)

    def __eq__(self, other):
        if self.rawname != other.rawname:
            return False
        return True

    def finish(self):
        """
        Finish parsing this function.
        """
        # Locate trailing padding instructions
        start_of_padding = len(self.instrs)
        for instr in self.instrs[::-1]:
            if instr.disasm == 'nop':
                start_of_padding -= 1
            break

        # Move padding instructions from self.instr to self.padding:
        self.padding = self.instrs[start_of_padding:]
        self.instrs = self.instrs[:start_of_padding]

        self.size = sum(len(instr.bytes_)
                        for instr in self.instrs)

    def get_instr_at_relative_offset(self, reloffset):
        offset = self.offset + reloffset
        for instr in self.instrs:
            if instr.offset == offset:
                return instr

class Section:
    def __init__(self, name):
        self.name = name

    def __eq__(self, other):
        return self.name == other.name

    def __ne__(self, other):
        return not self == other

hexgrp = r'([0-9a-f]+)'
opt_ws = '\s*'

def from_hex(str_):
    return HexInt(str_, 16)

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

    def get_demangled_function(self, demangled):
        for fn in self.functions.values():
            if fn.demangled == demangled:
                return fn

class ObjDump(AsmFile):
    """
    Parser for output from objdump -d
    """
    @classmethod
    def fixup_disasm(cls, disasm, rawfuncname, demangler):
        # Fixup jump offsets to refer to "THIS_FN" (to minimize changes due
        # to function renaming)
        m = re.match(r'.*\s([0-9a-f]+ \<.+\+0x[0-9a-f]+\>)', disasm)
        if m:
            m2 = re.match(r'[0-9a-f]+ \<(.+)\+(0x[0-9a-f]+)\>',
                          m.group(1))
            if m2.group(1) == rawfuncname:
                disasm = disasm[:m.start(1)] + 'THIS_FN+' + m2.group(2) + disasm[m.end(1):]

        # Fixup jumps to other functions by removing the offset within the
        # section, and demangling
        m = re.match(r'.*\s([0-9a-f]+) (\<.+\>)', disasm)
        if m:
            if m.group(2) != rawfuncname:
                disasm = (disasm[:m.start(1)]
                          + demangler.demangle(m.group(2)))

        return disasm

    def __init__(self, f, debug_level=0):
        AsmFile.__init__(self)
        self.debug_level = debug_level

        self.objpath = None
        self.fileformat = None

        self._demangler = Demangler()
        self.rootns = Scope('::')

        for line in f:
            if self.debug_level >= 3:
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
        if self.debug_level >= 1:
            print('SECTION: %s' % name)
        self._cur_section = Section(name)
        self.sections[name] = self._cur_section

    def _on_function(self, offset, name):
        if self.debug_level >= 1:
            print('FUNCTION:0x%x %s' % (offset, name))
        if self._cur_function:
            self._cur_function.finish()
        demangled = self._demangler.demangle(name)
        scopes = demangled.split('::')
        self._cur_function = Function(self._cur_section, offset, name, demangled, scopes[-1])
        curscope = self.rootns
        for scope in scopes[:-1]:
            if scope not in curscope:
                curscope[scope] = Scope(scope)
            curscope = curscope[scope]
        self.functions[name] = self._cur_function
        curscope[scopes[-1]] = self._cur_function

    def _on_instruction(self, offset, hexdump, disasm):
        if self.debug_level >= 2:
            print('INSTRUCTION:0x%x %r %r' % (offset, hexdump, disasm))
        disasm = self.fixup_disasm(disasm, self._cur_function.rawname,
                                   self._demangler)
        instr = Instruction(offset, hexdump, disasm)
        self._cur_function.instrs.append(instr)

def fn_equal(old, new):
    if len(old.instrs) != len(new.instrs):
        return False
    return all(oldinstr.disasm == newinstr.disasm
               for oldinstr, newinstr in zip(old.instrs, new.instrs))

def fn_diff(old, new, out, just_sizes):
    def handle_minor_changes():
        if old.rawname != new.rawname:
            out.writeln('  (renamed to %s)' % new.demangled)
        if old.section != new.section:
            out.writeln('  (moved from %s+%s to %s+%s)'
                        % (old.section.name, old.offset,
                           new.section.name, new.offset))
        elif old.offset != new.offset:
            out.writeln('  (moved offset within %s from %s to %s)'
                        % (old.section.name, old.offset, new.offset))

    if just_sizes:
        if old.size != new.size:
            out.writeln('Function %s changed size from %s to %s bytes'
                        % (old.demangled, old.size, new.size))
            if old.rawname != new.rawname:
                out.writeln('  (renamed to %s)' % new.demangled)
        return

    if fn_equal(old, new):
        out.writeln('Unchanged function: %s' % old.demangled)
        handle_minor_changes()
        return

    out.writeln('Changed function: %s' % old.demangled)
    handle_minor_changes()

    with out.indent():
        for oldinstr, newinstr in zip(old.instrs, new.instrs):
            if oldinstr.disasm == newinstr.disasm:
                out.writeln('FN+%04s: %s' % (HexInt(oldinstr.offset - old.offset), oldinstr.disasm))
            else:
                out.writeln('FN+%04s: Old: %s' % (HexInt(oldinstr.offset - old.offset), oldinstr.disasm))
                out.writeln('       : New: %s' % (newinstr.disasm, ))

class Peer:
    """
    A peer item for a MatchupSet
    """
    pass

class MatchupSet:
    """
    A matching-up of peers between two sets of items, old and new
    """
    def __init__(self, old, new):
        self.old = old
        self.new = new
        self.old_to_new = {}
        self.new_to_old = {}
        self.gone = []
        self.appeared = []
        for olditem in old.items():
            newitem = self._lookup(olditem)
            if newitem:
                self.old_to_new[olditem] = newitem
                self.new_to_old[newitem] = olditem
            else:
                self.gone.append(olditem)
        for newitem in new.items():
            if newitem not in self.new_to_old:
                self.appeared.append(newitem)

    def _lookup(self, olditem):
        raise NotImplementedError

class FunctionPeer(Peer):
    def __init__(self, asmfile):
        self.asmfile = asmfile
        self.fn_by_leafnames = {}
        for function in asmfile.functions.values():
            self.fn_by_leafnames[function.leafname] = function

    def items(self):
        return self.asmfile.functions.values()

class FunctionMatchupSet(MatchupSet):
    """
    Match up peer function names
    """
    def __init__(self, old, new):
        MatchupSet.__init__(self,
                            FunctionPeer(old),
                            FunctionPeer(new))

    def _lookup(self, olditem):
        rawname = olditem.rawname
        # Special case:
        # support "gimple_statement_d" becoming "gimple_statement_base"
        # (for http://gcc.gnu.org/ml/gcc-patches/2013-08/msg01788.html)
        rawname = rawname.replace('18gimple_statement_d',
                                  '21gimple_statement_base')
        if rawname in self.new.asmfile.functions:
            return self.new.asmfile.functions[rawname]
        if olditem.leafname in self.new.fn_by_leafnames:
            return self.new.fn_by_leafnames[olditem.leafname]

def asm_diff(old, new, out, just_sizes):
    out.writeln('Old: %s' % old.objpath)
    out.writeln('New: %s' % new.objpath)
    peers = FunctionMatchupSet(old, new)
    with out.indent():
        for gone in peers.gone:
            out.writeln('Function removed: %s' % gone)
        for appeared in peers.appeared:
            out.writeln('Function added: %s' % appeared)
        for oldfn, newfn in peers.old_to_new.items():
            fn_diff(oldfn, newfn, out, just_sizes)

class Output:
    def __init__(self, fileobj):
        self._indent = 0
        self.fileobj = fileobj

    def writeln(self, str_):
        self.fileobj.write('%s%s\n' % (self._indent * '  ', str_))

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
    asm_diff(old, new, Output(sys.stdout), just_sizes=False)
