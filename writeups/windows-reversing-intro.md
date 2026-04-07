#  1. Windows Reversing Intro

## What Is Reverse Engineering?

Reverse engineering in cybersecurity is the process of analyzing a compiled program — a binary — to understand what it does, without access to the original source code.

When a developer writes code in a language like C or C++, it gets compiled into machine code that the CPU can execute directly. Reverse engineering works backwards from that machine code to reconstruct the logic.

**Why it matters in security:**

-   Malware analysts use it to understand what malicious software actually does
-   It helps detect hidden functionality, obfuscation, or evasion techniques
-   It improves incident escalation quality when SOC analysts understand attacker tooling

----------

## How Programs Work at a Low Level

When you run a program, the following happens:

1.  High-level code is compiled into machine instructions
2.  Those instructions are loaded into memory
3.  The CPU executes them sequentially, with jumps and branches controlling flow

Inside a disassembler like IDA, you see those CPU instructions directly — this is called **assembly language**.

Assembly is not difficult to read because of syntax. It is difficult because context is missing. The analyst must rebuild that context through observation and pattern recognition.

----------

## Key Concept: The Calling Convention

A **calling convention** is a set of rules that defines how functions receive arguments and return values.

On 64-bit Windows, the convention used is called **fastcall**. The rules are:

Parameter

Register

1st

RCX

2nd

RDX

3rd

R8

4th

R9

5th+

Stack

**Why this matters:** When analyzing a function call, you look at what is loaded into RCX and RDX immediately before the call instruction. Those values are the arguments being passed to the function.

**Example from HelloWorld.exe:**

The instruction:

```
lea rcx, format
```

Loads the address of a format string into RCX — the first parameter. This tells us the function being called is likely `printf()`, even though IDA does not label it that way.

This is a core skill in reverse engineering: **inferring function identity from behavior and parameters**.

----------

## Strings and Why They Matter

Strings are readable text embedded inside binary files. They often reveal:

-   Output messages
-   File paths
-   Registry keys
-   URLs or domains
-   Commands or error messages

**How to find them in IDA:** `View → Open Subviews → Strings` (or `Shift + F12`)

Once found, you can follow **cross-references (XREFs)** to see exactly where in the code the string is used. This helps locate relevant functions quickly without reading the entire binary.

**SOC relevance:** Many malware samples leave strings behind. They are one of the fastest ways to extract indicators of compromise (IOCs) from a suspicious file.

----------

## Function Inlining (Compiler Optimization)

Function inlining is a compiler optimization where instead of calling a function, the compiler pastes the function's logic directly into the calling code.

**Without inlining:**

c

```c
int Add(int x, int y) { return x + y; }
int main() { int result = Add(x, 5); }
```

**With inlining:**

c

```c
int main() { int result = x + 5; }
```

The `Add` function disappears entirely.

**Why this matters for analysis:** If `std::cout` is only called once, the compiler may inline it — meaning you will not see a clean function call. Instead, the string appears directly inside a large block of code. This can be confusing if you do not know to expect it.

**The rule:** If a function appears more than once, inlining usually does not happen. If it appears only once, expect the possibility of inlining.

----------

##  Loop Analysis in Assembly

Loops in assembly do not look like `for` or `while`. They are built from three components:

1.  **A counter** — a register that tracks how many iterations have occurred
2.  **A condition** — a comparison that determines whether to continue
3.  **A jump** — an instruction that sends execution back to the top of the loop

**How to identify them:**

-   Look for a register being incremented (`inc RCX`)
-   Look for a comparison immediately after (`cmp RCX, RDX`)
-   Look for a conditional jump back (`jb loop_start`)

**From Loop.exe:**

```
inc rcx         ← counter increments each iteration
cmp rcx, rdx   ← compare counter to string length
jb  loop_start ← jump back if not finished
```

This tells us:

-   `RCX` is the loop counter (index into the string)
-   `RDX` is the total length of the string
-   The loop continues until every character has been checked

**What the loop was doing:** Each character was compared against the ASCII values for `a` (0x61) and `z` (0x7A). If it fell within that range, it was counted. The register `RBX` accumulated the total count of lowercase characters.

----------

## SOC Analyst Reflection

Reverse engineering is not a daily SOC task, but understanding it improves:

-   **Malware triage** — knowing what a binary is doing at a functional level
-   **Escalation quality** — providing DFIR teams with accurate behavioral context
-   **Threat intelligence** — understanding what capabilities malware actually has

The key lesson from this room is not the specific instructions. It is the mindset: **focus on patterns, not individual lines. Make assumptions, then validate them against observed behavior.**

----------
