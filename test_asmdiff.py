import unittest

from asmdiff import read_asm

class TestObjdumpParsing(unittest.TestCase):
    def parse_objdump(self):
        # This is the output from "objdump -Cd"
        # i.e. it's already gone through demangling
        return read_asm('examples/objdump/isra/tracer.old')

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

unittest.main()
