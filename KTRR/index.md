_Siguza, 17. Aug 2018_

# KTRR

Allegedly "Kernel Text Readonly Region".

### Introduction

This post tries to detail the mechanism used in Apple's A10 chips and later to prevent modification of an iOS kernel at runtime.  
Older chips attempt to do this via a monitor program loaded in EL3, which is inherently flawed and bypassable though as detailed in ["Tick Tock" by xerub](https://xerub.github.io/ios/kpp/2017/04/13/tick-tock.html).

### Notes

On some sites you'll see the term "memory-mapped registers" being thrown around. To avoid confusion I will not use that term, but instead:
- "Register" to mean actual registers such as those accessed by the arm64 `msr` instruction. Each CPU core has its own copy of such registers, and the values held by them will be lost when the core goes to sleep.
- "MMIO" (memory-mapped I/O) to mean a portion of the physical address that can be used to interact with a device on the SoC. Like regular RAM, this is global to the entire SoC and does not lose its values when any core goes to sleep, as it is a separate device.

Also note that code shown here will often have been shortened, expanding or removing macros that are assumed to be defined (`KERNEL_INTEGRITY_KTRR`, `MACH_BSD`, `__arm64__`) or not (`DEVELOPMENT`, `DEBUG`).

### Primitives

Besides abandoning EL3 altogether (leaving only EL1 and EL0), A10 chips introduce two new hardware features that serve as the corner stones for KTRR:

-   "RoRgn"  
    A piece of MMIO consisting of a "start", "end" and "lock" fields. The "lock" field, when   written to, will lock down all three fields, i.e. prevent any modification of them. The start and end fields hold numbers of pages in DRAM, spanning up the RoRgn. Inside this region, the memory controller will reject any and all attempted writes.  
    XNU has three macros to refer to them:
    ```c
    #define rRORGNBASEADDR (*(volatile uint32_t *) (amcc_base + 0x7e4))
    #define rRORGNENDADDR  (*(volatile uint32_t *) (amcc_base + 0x7e8))
    #define rRORGNLOCK     (*(volatile uint32_t *) (amcc_base + 0x7ec))
    ```
-   "KTRR registers"  
    A set of three registers added to every CPU core, holding "low", "high" and "lock" values respectively. The lock register, again, locks all three down. The low and high registers hold physical addresses, spanning up the executable range. If the CPU is at EL1 and the MMU is turned on, then any instruction fetch (i.e. trying to execute memory) outside of that range will fail, even if it is marked as executable in the page table. If the CPU is at EL0 or if the MMU is turned off, this range has no effect.  
    For those too, XNU has macros:
    ```c
    #define ARM64_REG_KTRR_LOWER_EL1                        S3_4_c15_c2_3
    #define ARM64_REG_KTRR_UPPER_EL1                        S3_4_c15_c2_4
    #define ARM64_REG_KTRR_LOCK_EL1                         S3_4_c15_c2_2
    ```

Also it is worth mentioning another feature that was present in past chips already, but is set up differently now:

-   "IORVBAR"  
    A piece of MMIO holding one field for every CPU, designating the physical address at which it will start executing on "reset" (basically when waking from sleep). This too has a locking mechanism, which is activated by writing to it a value that as its least significant bit set to 1.  
    On A9 CPUs and earlier this was set to a physical address inside TrustZone, where WatchTower (KPP) resides. Since A10, this is set to `LowResetVectorBase` as found in XNU, which iBoot calculates from the kernel's entry point as outlined by this comment:
    
    ```c
    /*
     * __start trampoline is located at a position relative to LowResetVectorBase
     * so that iBoot can compute the reset vector position to set IORVBAR using
     * only the kernel entry point.  Reset vector = (__start & ~0xfff)
     */
    ```

### In theory

The above primitives are virtually unbreakable due to their locking mechanism, but do by themselves not protect a running kernel. In order to look at what else is needed, we have to look a potential attacks:

0. (Asserted:) The primitives need to actually uphold what they promise.
1. It must be impossible for an attacker to disable any protections or choose to not enable them, thus they must be set up and locked down before the attacker can gain code execution.
2. It must be impossible for an attacker to patch any data you consider critical, so all of it needs to be inside the RoRgn. This sounds obvious in theory, but in practise a bunch of critical things are easily overlooked.
3. It must be impossible for an attacker to patch page tables that are used to map memory from the RoRgn, otherwise they can copy said memory to a writeable location and patch page tables to point there instead. Such page tables must thus be inside the RoRgn themselves.
4. It must be impossible for an attacker to employ a custom page table hierarchy, so the translation table base register that maps the kernel's half of the address space (`ttbr1_el1` in this case) must be unchangeable.
5. It must be impossible for an attacker to patch or inject any executable memory, otherwise they could add the instruction `msr ttbr1_el1, x0` and gain the ability to change `ttbr1_el1`. Therefore the "executable range" must be a strict subset of the RoRgn.
6. It must be impossible for an attacker to turn off the MMU, since when the MMU is off all pages are considered executable and an attacker could again inject `msr ttbr1_el1, x0`. The MMU status is controlled by the least significant bit of the register `sctlr_el1`, so said register must to be unchangeable as well during normal operation.
7. It must be impossible for an attacker to gain code execution before the MMU is turned on (for afore mentioned reasons). Since a CPU starts out with the MMU turned off when it wakes from sleep, this means IORVBAR must point to memory within the RoRgn, and any code executed before the MMU is turned on must not have its control flow controlled by data outside the RoRgn.

### In practice

So let's examine how iOS implements all of the above:

1.  IORVBAR is the first primitive to be fully set up, done so by iBoot before it jumps to the kernel's entry point. Loaded and locked down all in one go.  
    RoRgn gets its start and end values set by iBoot as well, but is not locked down yet. This is necessary because a lot of the data that is later readonly actually needs one-time initialisation, which is done by the kernel itself. I'll skip over most kernel bootstrapping here, but after setting up virtual memory and all const data including kexts, we arrive at `kernel_bootstrap_thread`, part of which reads:
    
    ```c
    machine_lockdown_preflight();
    /*
    *  Finalize protections on statically mapped pages now that comm page mapping is established.
    */
    arm_vm_prot_finalize(PE_state.bootArgs);

    kernel_bootstrap_log("sfi_init");
    sfi_init();

    /*
    * Initialize the globals used for permuting kernel
    * addresses that may be exported to userland as tokens
    * using VM_KERNEL_ADDRPERM()/VM_KERNEL_ADDRPERM_EXTERNAL().
    * Force the random number to be odd to avoid mapping a non-zero
    * word-aligned address to zero via addition.
    * Note: at this stage we can use the cryptographically secure PRNG
    * rather than early_random().
    */
    read_random(&vm_kernel_addrperm, sizeof(vm_kernel_addrperm));
    vm_kernel_addrperm |= 1;
    read_random(&buf_kernel_addrperm, sizeof(buf_kernel_addrperm));
    buf_kernel_addrperm |= 1;
    read_random(&vm_kernel_addrperm_ext, sizeof(vm_kernel_addrperm_ext));
    vm_kernel_addrperm_ext |= 1;
    read_random(&vm_kernel_addrhash_salt, sizeof(vm_kernel_addrhash_salt));
    read_random(&vm_kernel_addrhash_salt_ext, sizeof(vm_kernel_addrhash_salt_ext));

    vm_set_restrictions();



    /*
    * Start the user bootstrap.
    */
    bsd_init();
    ```
    The first thing we're interested in is `machine_lockdown_preflight`, which is just a wrapper around `rorgn_stash_range` that grabs the values computed by iBoot, translates them to physical addresses and stahes them in RoRgn memory for later:
    ```c
    void rorgn_stash_range(void)
    {
        /* Get the AMC values, and stash them into rorgn_begin, rorgn_end. */

        uint64_t soc_base = 0;
        DTEntry entryP = NULL;
        uintptr_t *reg_prop = NULL;
        uint32_t prop_size = 0;
        int rc;

        soc_base = pe_arm_get_soc_base_phys();
        rc = DTFindEntry("name", "mcc", &entryP);
        assert(rc == kSuccess);
        rc = DTGetProperty(entryP, "reg", (void **)&reg_prop, &prop_size);
        assert(rc == kSuccess);
        amcc_base = ml_io_map(soc_base + *reg_prop, *(reg_prop + 1));

        assert(rRORGNENDADDR > rRORGNBASEADDR);
        rorgn_begin = (rRORGNBASEADDR << ARM_PGSHIFT) + gPhysBase;
        rorgn_end   = (rRORGNENDADDR << ARM_PGSHIFT) + gPhysBase;
    }
    ```
    Next, `arm_vm_prot_finalize` patches page tables for the main kernel binary one last time before they become readonly, removing the writeable flag from all const and code regions.  
    And then, right before `bsd_init` there is a call to `machine_lockdown`, which is a wrapper around `rorgn_lockdown`. This call seems to have been `#ifdef`'ed out of public sources, but if we compare a few functions to some disassembly, it's evident a call to `machine_lockdown` was inlined there:
    ```c
    void rorgn_lockdown(void)
    {
        vm_offset_t ktrr_begin, ktrr_end;
        unsigned long plt_segsz, last_segsz;

        assert_unlocked();

        /* [x] - Use final method of determining all kernel text range or expect crashes */
        ktrr_begin = (uint64_t) getsegdatafromheader(&_mh_execute_header, "__PRELINK_TEXT", &plt_segsz);

        ktrr_begin = kvtophys(ktrr_begin);

        /* __LAST is not part of the MMU KTRR region (it is however part of the AMCC KTRR region) */
        ktrr_end = (uint64_t) getsegdatafromheader(&_mh_execute_header, "__LAST", &last_segsz);
        ktrr_end = (kvtophys(ktrr_end) - 1) & ~PAGE_MASK;

        /* [x] - ensure all in flight writes are flushed to AMCC before enabling RO Region Lock */
        assert_amcc_cache_disabled();

        CleanPoC_DcacheRegion_Force(phystokv(ktrr_begin), (unsigned)((ktrr_end + last_segsz) - ktrr_begin + PAGE_MASK));

        lock_amcc();

        lock_mmu(ktrr_begin, ktrr_end);

        /* now we can run lockdown handler */
        ml_lockdown_run_handler();
    }

    static void lock_amcc()
    {
        rRORGNLOCK = 1;
        __builtin_arm_isb(ISB_SY);
    }

    static void lock_mmu(uint64_t begin, uint64_t end)
    {
        __builtin_arm_wsr64(ARM64_REG_KTRR_LOWER_EL1, begin);
        __builtin_arm_wsr64(ARM64_REG_KTRR_UPPER_EL1, end);
        __builtin_arm_wsr64(ARM64_REG_KTRR_LOCK_EL1,  1ULL);

        /* flush TLB */
        __builtin_arm_isb(ISB_SY);
        flush_mmu_tlb();
    }
    ```
    ```
    0xfffffff0071322f4      8802134b       sub w8, w20, w19
    0xfffffff0071322f8      0801150b       add w8, w8, w21
    0xfffffff0071322fc      e9370032       orr w9, wzr, 0x3fff          // PAGE_MASK
    0xfffffff007132300      0101090b       add w1, w8, w9
    0xfffffff007132304      7c8dfe97       bl sym.func.fffffff0070d58f4 // CleanPoC_DcacheRegion_Force
    0xfffffff007132308      e8f641f9       ldr x8, [x23, 0x3e8]
    0xfffffff00713230c      1aed07b9       str w26, [x8, 0x7ec]         // rRORGNLOCK = 1;
    0xfffffff007132310      df3f03d5       isb
    0xfffffff007132314      73f21cd5       msr s3_4_c15_c2_3, x19       // ARM64_REG_KTRR_LOWER_EL1
    0xfffffff007132318      95f21cd5       msr s3_4_c15_c2_4, x21       // ARM64_REG_KTRR_UPPER_EL1
    0xfffffff00713231c      5af21cd5       msr s3_4_c15_c2_2, x26       // ARM64_REG_KTRR_LOCK_EL1
    0xfffffff007132320      df3f03d5       isb
    ```
    So within 5 instructions the kernel locks down the values iBoot preprogrammed for RoRgn, and initialised and locks down the KTRR registers as well.  
    Then it goes on to bootstrap the BSD subsystem, eventually leading to the creation of userland and the `launchd` process. This means that any exploit based on an app, WebKit, or even an untether binary will be much too late to do anything about KTRR. You'd need either a bootchain exploit, or one that runs very early during kernel bootstrap - which sounds rather infeasible in the presence of KASLR.
2.  There isn't much to discuss here, XNU simply had its segments rearranged in iOS 10 to fit this memory layout:
    ```
    Mem:    0xfffffff0057fc000-0xfffffff005f5c000   File: 0x06e0000-0x0e40000   r--/r-- __PRELINK_TEXT
    Mem:    0xfffffff005f5c000-0xfffffff006dd0000   File: 0x0e40000-0x1cb4000   r-x/r-x __PLK_TEXT_EXEC
    Mem:    0xfffffff006dd0000-0xfffffff007004000   File: 0x1cb4000-0x1ee8000   r--/r-- __PLK_DATA_CONST
    Mem:    0xfffffff007004000-0xfffffff007078000   File: 0x0000000-0x0074000   r-x/r-x __TEXT
    Mem:    0xfffffff007078000-0xfffffff0070d4000   File: 0x0074000-0x00d0000   rw-/rw- __DATA_CONST
    Mem:    0xfffffff0070d4000-0xfffffff00762c000   File: 0x00d0000-0x0628000   r-x/r-x __TEXT_EXEC
    Mem:    0xfffffff00762c000-0xfffffff007630000   File: 0x0628000-0x062c000   rw-/rw- __LAST
    Mem:    0xfffffff007630000-0xfffffff007634000   File: 0x062c000-0x0630000   rw-/rw- __KLD
    Mem:    0xfffffff007634000-0xfffffff0076dc000   File: 0x0630000-0x0664000   rw-/rw- __DATA
    Mem:    0xfffffff0076dc000-0xfffffff0076f4000   File: 0x0664000-0x067c000   rw-/rw- __BOOTDATA
    Mem:    0xfffffff0076f4000-0xfffffff007756dc0   File: 0x067c000-0x06dedc0   r--/r-- __LINKEDIT
    Mem:    0xfffffff007758000-0xfffffff0078c8000   File: 0x1ee8000-0x2058000   rw-/rw- __PRELINK_DATA
    Mem:    0xfffffff0078c8000-0xfffffff007b04000   File: 0x2058000-0x2294000   rw-/rw- __PRELINK_INFO
    ```
    RoRgn protects from `__PRELINK_TEXT` to `__LAST`, the executable range spans from `__PRELINK_TEXT` to `__TEXT_EXEC`.
3.  Yep, page tables used for the main kernel binary are in `__DATA_CONST` and appropriately named "ropagetable":
    ```asm
    /* reserve space for read only page tables */
            .align 14
    LEXT(ropagetable_begin)
            .space 16*16*1024,0
    ```
4.  In order for `ttbr1_el1` to be unchangeable, there must exist no instruction `msr ttbr1_el1, xN` in executable memory that an attacker could ROP into. It needs to exist _somewhere_ though because it is required for CPU reinitialisation after waking from sleep. But this isn't a problem, since at that time the MMU is still disabled and all memory is executable. So Apple created a new segment/section `__LAST.__pinst` (presumably "protected instructions") and moved there all instructions they consider critical, such as e.g. `msr ttbr1_el1, x0`. Since the `__LAST` segment is in the RoRgn but not in the executable range, it is only executable when the MMU is off.
5.  The executable range is a strict subrange of the RoRgn, so... check.
6.  Same story as for `ttbr1_el1`, there exists one instance of `msr sctlr_el1, x0` and that is in `__LAST.__pinst`.
7.  IORVBAR points to `LowResetVectorBase`, which is in `__TEXT_EXEC` and thus part of the RoRgn, so all CPUs start out in readonly memory after waking from sleep. The kernel isn't on the safe side yet as control flow could in theory still be redirected before the MMU is enabled (in `common_start` by means of `MSR_SCTLR_EL1_X0`), but in practice there seems to exist nothing that lets you redirect control flow. And even _if_ you managed that somehow, you would be able to change `ttbr1_el1` and "remap" const data and whatnot, but you'd still need to turn on the MMU on eventually, and in doing so you would again lose the ability to change either `ttbr1_el1` and `sctlr_el1`, as well as execute any injected code. This is because the absolute first thing the CPU does after waking from sleep is locking down the KTRR registers again:
    ```
        .text
        .align 12
        .globl EXT(LowResetVectorBase)
    LEXT(LowResetVectorBase)
        // Preserve x0 for start_first_cpu, if called

        // Unlock the core for debugging
        msr     OSLAR_EL1, xzr

        /*
         * Set KTRR registers immediately after wake/resume
         *
         * During power on reset, XNU stashed the kernel text region range values
         * into __DATA,__const which should be protected by AMCC RoRgn at this point.
         * Read this data and program/lock KTRR registers accordingly.
         * If either values are zero, we're debugging kernel so skip programming KTRR.
         */

        // load stashed rorgn_begin
        adrp    x17, EXT(rorgn_begin)@page
        add     x17, x17, EXT(rorgn_begin)@pageoff
        ldr     x17, [x17]
        // if rorgn_begin is zero, we're debugging. skip enabling ktrr
        cbz     x17, 1f

        // load stashed rorgn_end
        adrp    x19, EXT(rorgn_end)@page
        add     x19, x19, EXT(rorgn_end)@pageoff
        ldr     x19, [x19]
        cbz     x19, 1f

        // program and lock down KTRR
        // subtract one page from rorgn_end to make pinst insns NX
        msr     ARM64_REG_KTRR_LOWER_EL1, x17
        sub     x19, x19, #(1 << (ARM_PTE_SHIFT-12)), lsl #12 
        msr     ARM64_REG_KTRR_UPPER_EL1, x19
        mov     x17, #1
        msr     ARM64_REG_KTRR_LOCK_EL1, x17
    ```
    There's not even as much as a conditional branch here, nor any access to memory outside the RoRgn.

### Meltdown/Spectre mitigations (>=11.2)

For the uninitiated, Meltdown is one variant of Spectre, which is the name of a whole class of vulnerabilities found in virtually all modern processors. These vulnerabilities allow attackers to leak any data they like from any software running on that CPU if it doesn't take special countermeasures against that.  
For the iOS kernel, this means that it basically has to unmap its entire address space before dropping to EL0, and restoring that mapping once it returns to EL1. Given the care taken to make kernel page tables readonly and removing the ability to change `ttbr1_el1`, it seemed like mitigating Spectre would not be possible without breaking KTRR. But with a remarkably clever move, Apple did find a way. We're gonna need a bit of technical background for this though:

In ARMv8, translating virtual addresses to physical at EL0 and EL1 works as follows:
- `ttbr0_el1` provides the page table hierarchy for addresses from `0x0` on upwards to some point.
- `ttbr1_el1` provides the page table hierarchy for addresses from `0xffffffffffffffff` on downwards to some point.
- All addresses in between are invalid/unmapped.

Where exactly these two "certain points" are is configured via the `tcr_el1` register, specifically its `T0SZ` and `T1SZ` fields ([ARMv8 Reference Manual](https://static.docs.arm.com/ddi0487/ca/DDI0487C_a_armv8_arm.pdf), p. D10-2685 onwards). Specifically, the size of each range is `2^(64-T?SZ)` bytes (i.e. the larger `T?SZ`, the smaller the range). Since we're dealing in powers of two, adding or subtracting `1` to/from that field doubles or halves the size of the address range. So what Apple have done is rather simple:  
- They split the kernel's address space into two ranges. The first conatining only the bare minimum to switch between EL0 and EL1, the second containing the entire rest of the kernel.
- At boot, `T1SZ` is set to `25`, thus mapping the first range at `0xffffff8000000000` and the second one at `0xffffffc000000000` (for comparison, the unslid kernel base is `0xfffffff007004000`).
- When transitioning to EL0, `T1SZ` is increased to `26`, thus putting the first range at `0xffffffc000000000` and not mapping the second one at all anymore, and when coming back the value is restored to `25`.
- The exception vector is mapped into both ranges, to that `vbar_el1` is valid under either.

Fun fact: `tcr_el1` used to exist only in `__LAST.__pinst`, but has subsequently been brought back to normal executable memory since apparently it isn't _that_ critical after all.

### Possible attacks

Going through our list of 0-7 again, let's reason about what could be done on what level:

0.  (Hardware guarantees)  
    It might be possible to mount a rowhammer attack against protected memory and exploit the resulting bitflips. Similarly, given kernel memory access it might be possible to induce errors in all of CPU registers, DRAM and MMIO by changing their operating voltage if accessible, or by power glitching. (Please make sure to let me know about any results if you try that!)
1.  (Disable protections)  
    Anyone gaining code execution in iBoot or earlier can trivially just not enable KTRR, and iBoot vulnerabilities probably _do_ exist.
2.  (Critical data in RoRgn)  
    The only public KTRR bypass so far, by Luca Todesco, was based on precisely this. XNU has a `BootArgs` struct which, among other things, has fields that hold the physical and virtual base addresses of the end kernel, which are used when transitioning from physical to virtual memory (i.e. turning on the MMU). Prior to iOS 10.2, this struct was not in readonly memory, so it was possibly to hijak control flow. This was coupled with the fact that the code that ran on reset did not account for `__LAST.__pinst` and accidentally included it in the executable range.
3.  (Page tables for RoRgn inside RoRgn)  
    To the best of my knowledge this holds true, so there's no attack against this.
4.  (`ttbr1_el1` unchangeable)  
    The instruction `msr ttbr1_el1, x0` has been uniqued and exists only in `__LAST.__pinst` anymore, so I don't see how you would attack that either.
5.  (Shellcode injection)  
    Executable range is a subrange of RoRgn, so... that's a nope from me.
6.  (Turning off the MMU)  
    Same story as with `ttbr1_el1`.
7.  (Gaining code exec on reset)  
    Similarly to point 1, anyone gaining code execution after the CPU wakes from sleep but before the KTRR registers are locked down is off the hook. However, given the fact that this is pretty much the first thing any core does, the attack surface for this seems nonexistant.  
    Gaining code execution before the MMU is turned on would still be enough for most, but doesn't seem terribly likely either.

If none of these work, you'll simply have to make do with memory that _needs_ to be writeable at runtime and which Apple cannot protect. ¯\\\_(ツ)\_/¯
