This directory will contain the VHDL parser and related files.

To generate the ANTLR VHDL parser (if we choose that option), you would typically need to download the ANTLR tool and the VHDL grammar files, then run a command like this:

```bash
java -jar antlr-4.jar -Dlanguage=Python3 vhdl.g4
```

This is just an example; the exact process will depend on the parsing library we decide to use.
