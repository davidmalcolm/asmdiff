asmdiff
=======
This is a tool for comparing the output of "objdump" for a before/after
pair of .o files.

It attempts to be more useful than "diff" in the following ways:

  * It ignores reorderings of functions, instead matching them by name.

  * Functions that appear/disappear are reported by name, rather than
    emitting the body of the code.

  * Code locations and jump targets are tracked relative to the top of the
    function that they're in, so that movement of a function within the
    .text section doesn't show up as a difference.

  * Trailing nop instructions (for padding) are ignored
