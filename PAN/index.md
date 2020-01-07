_Siguza, 07. Jan 2020_

# PAN

Another day, another broken mitigation.

### Introduction

CPUs these days have a feature that prevents inadvertent memory accesses from the kernel to userland memory. Intel calls this feature "SMAP" (Supervisor Mode Access Prevention) while ARM calls it "PAN" (Privileged Access Never). Apple's A10 chips and later have this feature, meaning exploit payloads always need to be placed in kernel memory in some way, shape or form... or do they.  
At 0x41con 2019 I gave a talk about "Abusing Memory Access Protections", specifically on arm64. One of the bugs presented there was a PAN bypass that I had originally found in October 2018 when working on [Spice][spice] together with [lailo][lailo] and [Sparkey][Sparkey].

### Broken Dreams

The bug/bypass I had seems to have been independently discovered now, so I'll let [this Linux kernel commit message][commit] serve as a teaser:

    arm64: Revert support for execute-only user mappings
    The ARMv8 64-bit architecture supports execute-only user permissions by
    clearing the PTE_USER and PTE_UXN bits, practically making it a mostly
    privileged mapping but from which user running at EL0 can still execute.
    
    The downside, however, is that the kernel at EL1 inadvertently reading
    such mapping would not trip over the PAN (privileged access never)
    protection.

Now, of course I wouldn't just let that sit there without proof that I did indeed have this bug before today. ;)  
Back in October 2018 I tweeted out a hash: https://twitter.com/s1guza/status/1054785195239452673  
And here's how you can generate that hash yourself:

    $ curl 'https://siguza.github.io/PAN/tweet.txt' | shasum -a 512
    c0e0319a5e3a12e4a6394a50c67c860b17b566e0af24515ae9b357d1c671985603cb80daf873512adfb4f631c5138abe1381fcd31d6b99a14d1f9a5bbd6a3e38  -

The file contains my initial assessment of the bug so feel free to check it out, but since it would spoil most of this blog post, I decided to not copy-paste it here. ;)

### The Bug

As the commit message above gives away, the bug is plain and simple: `--x` memory doesn't trigger PAN.  
As for where it comes from and why it wasn't detected sooner, we'll have to circle back and revisit some basics - specifically memory access protections.

In our mental models, we usually think of memory protections as three independent bits: read, write and execute. And that makes sense, as it represents the three fundamental types of accesses that can happen. But that alone has a catch already, as the `mmap(2)` man page notes:

> Portable programs should not rely on these flags being separately enforcable.

But when looking at this from an OS-design perspective, the real issue is that this only represents the userland view. But accesses can really happen from both EL0 and EL1 while running off one and the same translation table entry, so at the end of the day, in order to accurately implement the model we have in our minds, you'd need 6 bits in total.

Let's look at how ARM does it. Here's two exhibits from the [ARMv8 Reference Manual][manual], specifically the TTE bits that make up access protections:

![TTE bits][img1]

![AP values][img2]

These entangled `AP` bits are a bit awkward to read, but surprisingly the ARMv7 Manual has a nicer breakout available for us:

![Real AP values][img3]

There are a few things to note here:

- As is evident, there are 4 bits for memory access protections, not 6.
- Execute permission has its own bit for EL0 and EL1 each, so is independent from the rest.
- There is no bit for read permission. You can take away write access. You can take away userland access. But you cannot take away read access at EL1, no matter what.

The last point is crucial. When you think of `--x` memory in userland, what the system sees is really `r--/--x` memory (in kernel/userland notation).  
But it's all good, PAN should see that userland has execute permission and prevent the access... ah who am I kidding, we all know it's broken at this point.

Memory access checks, including PAN, are handled by `AArch64.CheckPermission()` as given in the ARMv8 manual. This is the relevant part, PAN is handled in the last three lines, and I've highlighted the problematic part.

![AArch64.CheckPermission pseudocode][img4]

The description for the PAN feature reads:

> ### About PSTATE.PAN
> When the value of PSTATE.PAN is 1, any privileged data access from EL1, or EL2 when HCR_EL2.E2H is 1, to a virtual memory address that is accessible at EL0, generates a Permission fault.

And this is weird. Normally I have found the ARM manual to be pedantic and overly explicit, but in this instance they're vague - too vague, in fact. Because when they say "accessible", it's not clear what they mean. From the image above it's evident that "accessible" here means "has read permissions", but that is neither obvious nor reasonable, in my humble opinion.  
One could argue that rather than this being a bug in the specification, `--x` mappings are not supported and constitute misuse, however given the fact that [support for execute-only mappings in the Linux kernel was introduced by an ARM engineer][patch], I'd say that argument is pretty damn weak. And besides, there is no good reason for having PAN just _ignore_ the UXN bit, so I will put this down as a bug in the specification.

### Exploitability

This bug can be exploited on all ARMv8.1+ chips out there where the OS allows the creation of execute-only mappings.  
Linux used to be such an OS, up until yesterday (rest in RIP). I'll admit I have no idea about Windows. But I know that iOS was vulnerable not long ago, and to the best of my knowledge, still is at the time of writing. So let's say you can make the kernel dereference an arbitrary address, and let's look at what can be done with this bug under XNU.

The first thing to note is that "execute-only" could mean both `r--/--x` or `rw-/--x`, and that makes quite a difference. Matching my expectations though, XNU obviously uses `r--/--x`, so no fake mach ports there. It's definitely enough for fake vtables though, and most likely enough for a carefully crafted ROP stack that only uses gadgets that don't modify the stack. Additionally, this could be very interesting for dereferencing 32-bit values, or de-facto NULL derefs with an offset of a whole page or more (combined with some compiler flags like `-Wl,-pagezero_size,0x4000` :P).

Another thing to note is that the memory needs to be faulted in, probably best wired even. This can easily be done with `mlock`, but faulting in an executable mapping means it needs a valid code signature. Realistically that should be no issue though, since the two most likely attack vectors are from a side-loaded app and from WebContent, one of which can have `get-task-allow` and be allowed dirty executable pages, while the other has `dynamic-codesigning`.

### Fix pls?

So of course the obvious fix would be to replace that `user_r` in the ARMv8 specification with `(user_r || perms.xn == '0')`. But that comes a bit late now, so... hooray mitigations.  
Another obvious fix, as applied to the Linux kernel, is to simply forbid `--x` mappings now. I'm pretty sure that wouldn't bode too well with the WebKit folks and their "bulletproof JIT" however.  
A third option would be to invalidate `ttbr0_el1` on entry to the kernel and only restore it inside of `copyio`, but my guess is that this would come with an unacceptable performance hit.

On Apple's A10 chips and onward there is yet another option though, and actually one that should have really no downsides: APRR.  
If that Cryptic Apple Acronym™ doesn't ring a bell, I've done a [blog post on it][aprr] a few months ago. If you don't feel like reading that all, the TL;DR is that Apple's A10 chips and newer have a proprietary hardware feature that allows them to strip individual permission bits out of the effective access permission for each bit combination. So they could easily make `r--/--x` actually become `---/--x`.  
Ironically, if they had done this from the start, they would've also detected the info leak bug I dropped in the APRR post. :P  
And while Apple can only do this on A10 and later, all their earlier chips didn't have PAN anyway to begin with.

### Conclusion

This was quite fun. Even though the bug didn't live too long from the point I found it, finding a bug _in the specification_ has something unique and arcane to it.  
Also I'm not even too sad it got burned now. Because while it was a fun bug, the reality is that, in practice, PAN was never even an issue to get around. :P

On a separate note, defensive security folks, and Apple in particular, loooooove mitigations. On iOS, Apple has lately been slapping proprietary mitigations around like there's no tomorrow.  
But thing is, mitigations are often delicate creatures, with rather fragile assumptions. Having too many of them in one place can easily make them break one another, as happened here with execute-only memory vs PAN. And this isn't the first time either, in my blog post about APRR it was ASLR that got broken by another mitigation, and there are a few more cases like this that I know of. As the number of mitigations around specific features increase, I expect collisions like these to become more common. But hey, something has to stay fun, right? :P

As always, feedback is greatly welcome (as is unrelated security chatter :P)! You can [find me on Twitter][twitter] or reach me via email (`*@*.net` where `*` = `siguza`). :)

With that said, I think there's nothing left to do but to wish you all a good one, give a hat tip to the folks who were at 0x41con, and show you the last slide of my deck:

![Conclusions][img5]

  [spice]: https://media.ccc.de/v/36c3-11034-tales_of_old_untethering_ios_11
  [lailo]: https://twitter.com/littlelailo/
  [sparkey]: https://twitter.com/iBSparkes/
  [commit]: https://git.kernel.org/pub/scm/linux/kernel/git/torvalds/linux.git/commit/?id=24cecc37746393432d994c0dbc251fb9ac7c5d72
  [tweet]: https://twitter.com/s1guza/status/1054785195239452673
  [manual]: https://developer.arm.com/docs/ddi0487/latest
  [img1]: assets/img/1-ttebits.png
  [img2]: assets/img/2-access.png
  [img3]: assets/img/3-realaccess.png
  [img4]: assets/img/4-pseudo.png
  [patch]: https://lore.kernel.org/patchwork/patch/706340/
  [aprr]: https://siguza.github.io/APRR/
  [img5]: assets/img/5-conclusions.png
  [twitter]: https://twitter.com/s1guza/
