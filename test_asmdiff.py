import unittest

from asmdiff import read_objdump, FunctionPeers, fn_equal

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
        self.assertEqual(fn.name, 'gate_tracer()')
        self.assertEqual(len(fn.instrs), 13)
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

class TestDiff(unittest.TestCase):
    def test_adding_anon_namespace(self):
        old = read_objdump('examples/objdump/anon-namespace/tracer.old')
        new = read_objdump('examples/objdump/anon-namespace/tracer.new')
        peers = FunctionPeers(old.functions.keys(), new.functions.keys())
        self.assertEqual(peers.gone, [])
        self.assertEqual(peers.appeared, [])
        self.assertEqual(
            peers.old_to_new['tracer_state::find_trace(basic_block_def*, basic_block_def**)'],
            '(anonymous namespace)::tracer_state::find_trace(basic_block_def*, basic_block_def**)')

        oldfn = old.functions['gate_tracer()']
        newfn = new.functions['gate_tracer()']
        self.assertTrue(fn_equal(oldfn, newfn))

unittest.main()
