#   Copyright 2013, 2023 David Malcolm <dmalcolm@redhat.com>
#   Copyright 2013, 2023 Red Hat, Inc.
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
import io
import unittest

from asmdiff import read_objdump, FunctionMatchupSet, fn_equal, \
    Instruction, Demangler, ObjDump, Output, asm_diff

class TestObjdumpParsing(unittest.TestCase):
    def parse_objdump(self):
        # This is the output from "objdump -Cd"
        # i.e. it's already gone through demangling
        return read_objdump('examples/objdump/isra/tracer.old')

    def test_parsing(self):
        asm = self.parse_objdump()
        self.assertEqual(asm.objpath,
                         'gcc-build/test/control/build/gcc/tracer.o')
        self.assertEqual(asm.fileformat, 'elf64-x86-64')

        self.assertIn('.text', asm.sections)

        self.assertIn('gate_tracer()', asm.functions)
        fn = asm.functions['gate_tracer()']
        self.assertEqual(fn.rawname, 'gate_tracer()')
        self.assertEqual(len(fn.instrs), 13)
        self.assertEqual(fn.section.name, '.text')
        self.assertEqual(fn.offset, 0x0)

        """
        0000000000000000 <gate_tracer()>:
           0:   8b 0d 00 00 00 00       mov    0x0(%rip),%ecx        # 6 <gate_tracer()+0x6>
           6:   31 c0                   xor    %eax,%eax
           8:   85 c9                   test   %ecx,%ecx
           a:   7e 15                   jle    21 <gate_tracer()+0x21>
           c:   8b 15 00 00 00 00       mov    0x0(%rip),%edx        # 12 <gate_tracer()+0x12>
          12:   85 d2                   test   %edx,%edx
          14:   74 0b                   je     21 <gate_tracer()+0x21>
          16:   8b 05 00 00 00 00       mov    0x0(%rip),%eax        # 1c <gate_tracer()+0x1c>
          1c:   85 c0                   test   %eax,%eax
          1e:   0f 95 c0                setne  %al
          21:   f3 c3                   repz retq
          23:   66 66 66 66 2e 0f 1f    data32 data32 data32 nopw %cs:0x0(%rax,%rax,1)
          2a:   84 00 00 00 00 00
        """
        i1 = fn.instrs[1]
        self.assertEqual(i1.offset, 0x6)
        self.assertEqual(i1.bytes_, [0x31, 0xc0])
        self.assertEqual(i1.disasm, 'xor    %eax,%eax')

        # Verify that offsets are rewritten relative to "THIS_FN"
        i3 = fn.instrs[3]
        self.assertEqual(i3.offset, 0xa)
        self.assertEqual(i3.bytes_, [0x7e, 0x15])
        self.assertEqual(i3.disasm, 'jle    THIS_FN+0x21')

    def test_demangling(self):
        asm = read_objdump('examples/objdump/add-classes/tracer.new')
        RAWNAME = '_ZN12tracer_state19find_best_successorEP15basic_block_def'
        self.assertIn(RAWNAME, asm.functions)
        fn = asm.functions[RAWNAME]
        self.assertEqual(fn.rawname, RAWNAME)
        self.assertEqual(fn.demangled,
                         'tracer_state::find_best_successor(basic_block_def*)')
        self.assertEqual(fn.offset, 0x560)
        self.assertEqual(fn.section.name, '.text')

class TestDiff(unittest.TestCase):
    def read_anon_namespace_files(self):
        old = read_objdump('examples/objdump/anon-namespace/tracer.old')
        new = read_objdump('examples/objdump/anon-namespace/tracer.new')
        return old, new

    def get_diff(self, old, new, just_sizes=False):
        """
        Run the diff tool, getting the output as a str
        """
        strio = io.StringIO()
        asm_diff(old, new, Output(strio), just_sizes)
        return strio.getvalue()

    def test_adding_anon_namespace(self):
        old, new = self.read_anon_namespace_files()
        peers = FunctionMatchupSet(old, new)
        self.assertEqual(peers.gone, [])
        self.assertEqual(peers.appeared, [])
        oldfn = old.get_demangled_function(
            'tracer_state::find_trace(basic_block_def*, basic_block_def**)')
        self.assertIn(oldfn, peers.old_to_new)
        newfn = peers.old_to_new[oldfn]
        self.assertEqual(
            newfn.demangled,
            '(anonymous namespace)::tracer_state::find_trace(basic_block_def*, basic_block_def**)')

        oldfn = old.functions['gate_tracer()']
        newfn = new.functions['gate_tracer()']
        self.assertTrue(fn_equal(oldfn, newfn))

        # Some functions move from their own sections to the .text section:
        oldfn = old.get_demangled_function(
            'tracer_state::bb_seen_p(basic_block_def*)')
        self.assertIn(oldfn, peers.old_to_new)
        newfn = peers.old_to_new[oldfn]
        self.assertEqual(
            newfn.demangled,
            '(anonymous namespace)::tracer_state::bb_seen_p(basic_block_def*)')
        self.assertEqual(oldfn.section.name,
                         '.text._ZN12tracer_state9bb_seen_pEP15basic_block_def')
        self.assertEqual(oldfn.offset, 0x0)
        self.assertEqual(newfn.section.name, '.text')
        self.assertEqual(newfn.offset, 0x3b6)

        # Currently bb_seen_p is reported as having changed, purely due to
        # the following 5-byte instruction:
        #
        #    FN+0x1f: Old: callq  THIS_FN+0x24
        #           : New: callq  <bitmap_bit_p(simple_bitmap_def const*, int)>
        #  Old: e8 00 00 00 00
        #  New: e8 c8 fd ff ff
        # In the old function, bitmap_bit_p is in a different section,
        # whereas in the new they are both in the .text section.
        # Presumably in the old object this call gets patched based on where
        # the callee ends up
        # Ultimately we need "objdump -r" to see the relocations
        old_callq = oldfn.get_instr_at_relative_offset(0x1f)
        new_callq = newfn.get_instr_at_relative_offset(0x1f)
        self.assertEqual(old_callq.disasm,
                         'callq  THIS_FN+0x24')
        self.assertEqual(new_callq.disasm,
                         'callq  <bitmap_bit_p(simple_bitmap_def const*, int)>')

        out = self.get_diff(old, new)
        self.assertIn('Old: tracer.o\n', out)
        self.assertIn('New: tracer.o\n', out)
        self.assertIn('  Unchanged function: ei_container(edge_iterator)\n', out)
        self.assertIn(('\n'
                       '  Unchanged function: gate_tracer()\n'
                       '    (moved offset within .text from 0x11a8 to 0x1236)\n'),
                      out)
        self.assertIn(('\n'
                       '  Unchanged function: tracer_state::find_best_successor(basic_block_def*)\n'
                       '    (renamed to (anonymous namespace)::tracer_state::find_best_successor(basic_block_def*))\n'
                       '    (moved offset within .text from 0x560 to 0x5ee)\n'),
                      out)
        # tracer_state::bb_seen_p(basic_block_def*):
        self.assertIn('    (moved from .text._ZN12tracer_state9bb_seen_pEP15basic_block_def+0x0 to .text+0x3b6)',
                      out)


    def test_trailing_nops(self):
        old, new = self.read_anon_namespace_files()
        FNNAME = 'loops_state_set(unsigned int)'
        oldfn = old.functions[FNNAME]
        newfn = new.functions[FNNAME]
        self.assertEqual(oldfn.padding, [])
        self.assertEqual(newfn.padding, [Instruction(0x353, [144], 'nop')])
        self.assertTrue(fn_equal(oldfn, newfn))

    def test_adding_classes(self):
        old = read_objdump('examples/objdump/add-classes/tracer.old')
        new = read_objdump('examples/objdump/add-classes/tracer.new')
        peers = FunctionMatchupSet(old, new)
        # Verify that it matches up various functions that become
        # methods of class tracer_state:
        self.assertEqual(peers.gone, [])
        self.assertEqual(peers.appeared, [])

        oldfn = old.get_demangled_function(
            'find_best_predecessor(basic_block_def*)')
        newfn = peers.old_to_new[oldfn]

        oldinstr = oldfn.get_instr_at_relative_offset(0xaa)
        newinstr = newfn.get_instr_at_relative_offset(0xaa)
        # This changes from:
        #  FN+0xaa: Old: callq  3e1 <ignore_bb_p(basic_block_def const*)>
        #         : New: callq  353 <ignore_bb_p(basic_block_def const*)>
        # which isn't really a change
        self.assertEqual(oldinstr.disasm, 'callq  <ignore_bb_p(basic_block_def const*)>')
        self.assertEqual(newinstr.disasm, 'callq  <ignore_bb_p(basic_block_def const*)>')

        out = self.get_diff(old, new)
        self.assertIn(('\n'
                       '  Changed function: tail_duplicate()\n'
                       '    (renamed to tracer_state::tail_duplicate())\n'),
                      out)

    def test_size_diff(self):
        old = read_objdump('examples/objdump/add-classes/tracer.old')
        new = read_objdump('examples/objdump/add-classes/tracer.new')
        out = self.get_diff(old, new, just_sizes=True)
        self.assertEqual(out,
                         ('Old: examples/objdump/add-classes/tracer.old\n'
                          'New: examples/objdump/add-classes/tracer.new\n'))

class TestDemangler(unittest.TestCase):
    def test_demangling(self):
        d = Demangler()
        self.assertEqual(d.demangle('_ZL12mark_bb_seenP15basic_block_def'),
                         'mark_bb_seen(basic_block_def*)')
        self.assertEqual(d.demangle('_ZN3vecIP8edge_def5va_gc8vl_embedEixEj'),
                         'vec<edge_def*, va_gc, vl_embed>::operator[](unsigned int)')

class TestFixupDisasm(unittest.TestCase):
    demangler = Demangler()

    def test_fixup_within_fn(self):
        self.assertEqual(
            ObjDump.fixup_disasm(
                'mov    0x0(%rip),%rax        # 78e <tracer_state::find_trace(basic_block_def*, basic_block_def**)+0x1e>',
                'tracer_state::find_trace(basic_block_def*, basic_block_def**)',
                self.demangler),
            'mov    0x0(%rip),%rax        # THIS_FN+0x1e')

    def test_fixup_calling_other_fn(self):
        self.assertEqual(
            ObjDump.fixup_disasm(
                'callq  3e1 <_ZL11ignore_bb_pPK15basic_block_def>',
                None,
                self.demangler),
            'callq  <ignore_bb_p(basic_block_def const*)>')

unittest.main()
