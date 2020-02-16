# ELF Hijacking via PLT/GOT Poisoning
[![Build Status](https://travis-ci.org/khale/elf-hijack.svg?branch=master)](https://travis-ci.org/khale/elf-hijack)

## The Basics
This PoC demonstrates how to infect a running process on a system in order to
hide and later trigger code under an attacker's control. An attacker-controlled, parasitic
shared library is forced to be loaded into the target process, and a function
used normally by the process is redirected to point to a nefarious function living
in the parasite library. The basic
process is as follows:

1. The parasite library is built by the attacker (in our case `libtest.so.1.0`) that overrides a function which
is known to exist in the address space of the target process (and which
is known to be used by the target program). For example, `printf` is a good
bet, since it lives in `libc` and is pretty commonly used. Our example does
this using a function called `evilprint()`, which prints "I am evil." rather
than the original `printf()` arguments.

2. Once an attacker compromises a system (and gets privilege), this
parasite library is brought onto the compromised system, along with an attack tool.

3. The attack tool (in our case `p01snr`) is run (as root) and uses 
`ptrace` to attach to the target process. This will *only* work 
as a root user. 

4. After attaching, the attack tool injects some shellcode into the target process's
code segment (`.text`) (using `ptrace(POKE_TEXT)`). The purpose of this shellcode is
to `open()` and subsequently `mmap()` the shared library into the target process's
address space. Newer systems will prevent this sort of code injection, in which case more
clever use of `ptrace()` is necessary. See [countermeasures](#countermeasures) for
more detail.

5. The attack tool now uses `ptrace()` to invoke the `mmap()` shellcode (using
`ptrace(PTRACE_CONT)`). It then restores the original code in `.text` that
was overwritten in the previous code injection step. At this point the
attacker's library is loaded into the target process (which can be verified
by inspecting `/proc/<PID>/maps` of the target process). 

6. Now that the library is loaded,  the attack tool overrides the original
target function (`printf()`) with the attacker's function inside the parasite library
(`evilprint()`). It does this by patching the GOT entry corresponding to the
target function.  The attack tool can find the GOT by reading the memory image
of the target process at the location where the target program's binary is
mapped. This way it can parse the ELF binary and thus find the GOT location.
The GOT entry for `printf()` is overridden with `evilprint()`, thus redirecting
any future calls of the target function to the parasite library. To make this work, the attacker
needs to know the address of the overriding function in the parasite library. One way to
find this easily is to use a function signature (first few bytes of the object
code) to do pattern matching of the library's binary. That's exactly what this
PoC does. See `scripts/extract_func_sig.sh`.

7. The previous will *completely* override the original target function. One
behavior that might be beneficial is to instead orverride it, but then after our
overriding function is invoked, invoke the original target function as well. In our
case, that would mean that `evilprint()` does what it needs to, then invokes
`printf()`.  This gives us the ability to make it look to the program like
nothing has changed. In order for this to occur, the overriding function cannot
just directly invoke the original (think about why). Instead, the overriding function contains
an obvious call via function pointer to a place-holder address. The attack tool
will then play the role of the dynamic linker at runtime and patch this place-holder
address with the address of the target function (`printf()`). It does this by
looking for a instruction signature of the obvious call (referred to as
"transfer code" within the PoC) and patching it.

That's the basic structure of the attack. 

## Countermeasures

There are a few countermeasures that can prevent this kind of attack from happening:

* Prevent privilege escalation. If an attacker can't get root, they can't `ptrace(PTRACE_ATTACH)` to a target process, rendering this attack impossible.
* Compile long-running programs statically. In statically compiled binaries, there is no dynamic linking, no GOT, and no shared libraries, so short of rewriting the program's binary, there's no way to perform this attack. Even binary rewriting will likely be impossible due to the next countermeasure. Static linking is not a realistic option for large programs and for heavily used systems, since processes which use the library will duplicate it in memory, wasing sapce. Binary image sizes will skyrocket.
* Use Linux GRSEC patches. These Linux kernel patches prevent (among other things)
modifications to a program's `.text` segment by a tracer using `ptrace()`. However,
we can get around this by avoiding the use of shellcode entirely. We instead
write our system call arguments into the `.data` section of the target, and use
`ptrace(PTRACE_SYSCALL)` to cause the target to stop *before* the execution of
its next system call. We then change the registers (again using `ptrace`) 
to invoke a series of *different* syscalls (in our case `open()` followed by `mmap()`)
which has the same effect of loading the attack library. The program is the reset
to what it was doing before. This work-around is done by our PoC, and you can see
it in action in `grsec_mmap_library()`. 



## Usage

There are three components to this PoC. The first is a simple target process
(called `daemon`) which sits in the background and prints a string every few
seconds. The second is the parasite library (`libtest.so.1.0`, implemented in
`parasite.c`) which has an overriding function for `printf` called
`evilprint()`. Once this library is injected into the target, it will print "I
am evil" instead of the original print. The third component is the injection
tool, called `p01snr`. You can learn about its options by running it without
arguments (`./p01snr`). You'll probably want to provide the `-g` flag to
bypass the GRSEC code injection protection (so that our attack will use
the method outlined in the previous section). The attack will not likely
work without this flag on newer systems.


```
$ make
$ sudo make install
$ ./daemon & 
```

The first command builds all the code, in addition to autogenerating the
`mmap()` shellcode payload based on some assembly and autogenerating 
the function signature string for our attack function. You should
take a look at how these are generated by looking at `scripts/gen_mmap.sh`, 
`scripts/gen_shellcode.sh`, and `scripts/extract_func_sig.sh`.

The second command installs the parasite library into a directory 
on the default library search path, in this case `/lib`. 

The third command invokes the target as a background process. Once you run
this, keep track of the PID that the shell outputs for the `daemon`. If you lose
track of it, you can find it later on with `ps aux | grep daemon`. 

Once we have the PID of the `daemon` process, we can attack it as follows:

```
$ sudo ./p01snr -p PID -f puts -l libtest.1.0.so -g
```

Note that we *must* run this command as root, otherwise the attack tool
will not be able to `ptrace(PTRACE_ATTACH)` to the target process. 

You should now see the daemon hijacked (evident from it printing "I am evil.").

## Acknowledgements
The PoC code here was originally (way back in 2013) taken from a great [article](https://vxjes.us/papers/Neill%20'Modern%20Day%20ELF%20Runtime%20infection%20via%20GOT%20poisoning.html#c11) by Ryan ([elfmaster](https://twitter.com/ryan_elfmaster)) O'Neill. I've since modified it and adapted it for a security class, and added some tools to autogenerate payloads. For more great ELF hackery I recommend perusing his [github](https://github.com/elfmaster).
