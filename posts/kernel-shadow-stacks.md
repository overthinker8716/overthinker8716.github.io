title: [EN] The stack the kernel cannot write to
date: 2026-11-12

I kept getting stuck on one thing while reading about kernel CET on Windows. The threat model for the kernel assumes the attacker already has arbitrary write. So the shadow stack has to be unwritable from ring 0. But every `call` in the kernel writes to it. Both can't be true with normal paging, and it took me a while to see where the trick is.

These are my notes. Most of it comes from other people's reversing, linked at the bottom.

## What CET gives you, and what it doesn't

Quick recap. With CET on (`CR4` bit 23, plus bit 0 of `IA32_S_CET`, MSR `0x6A2`), return addresses get pushed twice: once on the normal stack, once on a second stack pointed to by `SSP`. For ring 0 that pointer comes from `IA32_PL0_SSP` (`0x6A4`).

```c
void ret(void)
{
    uint64_t expected = shadow_pop(ssp);
    uint64_t actual = pop(rsp);

    if (actual != expected)
        raise(CONTROL_PROTECTION_FAULT, NEAR_RET);

    rip = actual;
}
```

Smash a return address and you get `#CP` instead of a ROP chain. Fine.

Now, how does the CPU know a page is a shadow stack? From the PTE: present, not writable, dirty. A combination that makes no sense otherwise.

```c
bool is_shadow_stack_page(PTE pte)
{
    return pte.present && !pte.write && pte.dirty;
}
```

A regular `mov` to that page faults. In user mode that's the end of the story, the page tables are out of reach.

In the kernel it's useless on its own. PTEs are kernel memory. With a write primitive I flip `R/W`, patch the return address, flip it back. Or I don't even bother with permissions and just point the PTE at a physical page I control. Satoshi Tanda lays out both in his post and I don't see a third option worth mentioning.

So whatever protects the shadow stack can't live in the guest page tables.

## Bit 60

HVCI already gives Windows a place the kernel can't touch: the EPT, owned by the hypervisor. First idea, mark the shadow stack frames read-only in there.

That doesn't work, and this is the part I had missed. A `call` writes to the frame. Read-only in EPT means an EPT violation, so a VM exit, on every call instruction in the kernel. Nobody ships that.

Intel added a bit for exactly this case. If bit 7 of the EPTP is set, bit 60 of a leaf entry means "supervisor shadow stack page".

```c
typedef union _EPT_LEAF {
    uint64_t value;
    struct {
        uint64_t read : 1;
        uint64_t write : 1;
        uint64_t execute : 1;
        uint64_t memory_type : 3;
        uint64_t ignore_pat : 1;
        uint64_t large_page : 1;
        uint64_t accessed : 1;
        uint64_t dirty : 1;
        uint64_t user_execute : 1;
        uint64_t : 1;
        uint64_t frame : 40;
        uint64_t : 5;
        uint64_t verify_guest_paging : 1;
        uint64_t paging_write : 1;
        uint64_t : 1;
        uint64_t supervisor_shadow_stack : 1;
        uint64_t sub_page_write : 1;
        uint64_t : 1;
        uint64_t suppress_ve : 1;
    };
} EPT_LEAF;
```

The frame is mapped `write = 0`, `supervisor_shadow_stack = 1`. Shadow stack accesses go through with no exit. Data writes hit `write = 0` and die, whatever the guest PTE says.

It also kills the remapping attack, from the other side: a shadow stack access is only allowed on a frame that has the bit. Point the PTE at your own page and the next `call` faults, because your page isn't marked.

AMD has the same thing (SSSCheck), encoded differently in the nested page tables. I haven't looked at it closely.

## NT can't allocate its own stacks anymore

Only VTL1 can ask the hypervisor to change what VTL0 sees. Which means creating a thread now involves the Secure Kernel:

```text
nt!PspAllocateThread
  nt!KeInitThread
    nt!KiCreateKernelShadowStack
      nt!MmCreateKernelStack
        nt!MiAllocateKernelStackPages
          nt!VslAllocateKernelShadowStack
            ======== secure call ========
            securekernel!SkmmCreateNtKernelShadowStack
              securekernel!SkmiClaimPhysicalPage
                HvCallModifyVtlProtectionMask
              securekernel!SkmiInitializeNtKernelShadowStack
```

These names are from Connor McGarr's write-up and will move between builds.

What I like here is the ordering. The Secure Kernel takes the frames, drops VTL0 write access, zeroes them, then writes the initial content itself (the token at the top, and the address the thread starts from). There is never a window where NT has the page mapped writable.

A secure call per thread creation is slow, so freed shadow stacks are cached per processor and per NUMA node, still protected.

## The part that looks fragile

`ret` isn't the only way out of a function. Exceptions, unwinding, restoring a `CONTEXT`: all of these leave `SSP` pointing at frames that are gone. And NT can't fix up a stack it can't write to. So it asks:

```text
nt!KeKernelShadowStackRestoreContext
  nt!VslKernelShadowStackAssist
    ======== secure call ========
    securekernel!SkmmNtKernelShadowStackAssist
      securekernel!SkmiNtKssAssistDispatch
        securekernel!SkmiNtKssAssistRestore
```

VTL1 checks the `SSP` it's being asked to set against what it knows about that thread's shadow stack, then sets it through the hypervisor.

If I were looking for bugs, I'd start there. You can't write the shadow stack, but you can ask VTL1 to move the pointer for you, and everything depends on how strict that check is. McGarr also mentions in his Black Hat talk that on a `#CP` the handler looks for the bad return address further down the shadow stack and carries on if it finds it. I haven't reproduced that and I don't know yet how much room it leaves. That's the next thing I want to look at.

## Is it on?

Not by default the last time I checked, and it needs HVCI. The settings live here:

```powershell
$scenarios = 'HKLM:\SYSTEM\CurrentControlSet\Control\DeviceGuard\Scenarios'
Get-ItemProperty "$scenarios\HypervisorEnforcedCodeIntegrity", "$scenarios\KernelShadowStacks"
```

## Reading

- Connor McGarr, [Out Of Control: KCFG and KCET](https://i.blackhat.com/BH-USA-25/Presentations/USA-25-McGarr-Out-Of-Control-KCFG-And-KCET.pdf) (Black Hat USA 2025) and his [post on kernel-mode shadow stacks](https://connormcgarr.github.io/km-shadow-stacks)
- Satoshi Tanda, [What keeps kernel shadow stack effective against kernel exploits?](https://tandasat.github.io/blog/2025/04/02/sss.html)
- Aulnette and Jullian, [Windows kernel shadow stack mitigation](https://www.sstic.org/media/SSTIC2025/SSTIC-actes/windows_kernel_shadow_stack_mitigation/SSTIC2025-Article-windows_kernel_shadow_stack_mitigation-aulnette_jullian.pdf) (SSTIC 2025)
