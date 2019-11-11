# ucore_lab1实验报告   (朱俊峰 4042017045)
## 练习1 理解通过make生成执行文件的过程。（要求在报告中写出对下述问题的回答）
> 列出本实验各练习中对应的OS原理的知识点，并说明本实验中的实现部分如何对应和体现了原理中的基本概念和关键知识点。   
>在此练习中，大家需要通过静态分析代码来了解：  
1、操作系统镜像文件ucore.img是如何一步一步生成的？(需要比较详细地解释Makefile中每一条相关命令和命令参数的含义，以及说明命令导致的结果)  
2、一个被系统认为是符合规范的硬盘主引导扇区的特征是什么？

## 练习1.1
## 1、生成`ucore.img`的代码如下
```
$(UCOREIMG): $(kernel) $(bootblock)
    $(V)dd if=/dev/zero of=$@ count=10000
    $(V)dd if=$(bootblock) of=$@ conv=notrunc
    $(V)dd if=$(kernel) of=$@ seek=1 conv=notrunc
$(call create_target,ucore.img)
```
创建一个大小为10000字节的`bootblock`  
为了生成`ucore.img`，首先需要生成`bootblock`、`kernel`
## 2、生成`bootblock`的相关代码为
```
$(bootblock): $(call toobj,$(bootfiles)) | $(call totarget,sign) 
    @echo "========================$(call toobj,$(bootfiles))"
    @echo + ld $@
    $(V)$(LD) $(LDFLAGS) -N -e start -Ttext 0x7C00 $^ -o $(call toobj,bootblock)
    @$(OBJDUMP) -S $(call objfile,bootblock) > $(call asmfile,bootblock)
    @$(OBJCOPY) -S -O binary $(call objfile,bootblock) $(call outfile,bootblock)
    @$(call totarget,sign) $(call outfile,bootblock) $(bootblock)

```
为了生成`bootblock`，首先需要生成`bootasm.o`、`bootmain.o`、`sign`  
1、生成`bootasm.o`、`bootmain.o`
```
bootfiles = $(call listf_cc,boot)
$(foreach f,$(bootfiles),$(call cc_compile,$(f),$(CC),$(CFLAGS) -Os -nostdinc))
```
2、生成`bootasm.o`需要`bootasm.S`
```
gcc -Iboot/ -fno-builtin -Wall -ggdb -m32 -gstabs -nostdinc  -fno-stack-protector -Ilibs/ -Os -nostdinc -c boot/bootasm.S -o obj/boot/bootasm.o
```
其中的参数为
>-ggdb  生成可供gdb使用的调试信息。这样才能用qemu+gdb来调试bootloader or ucore。  
-m32  生成适用于32位环境的代码。我们用的模拟硬件是32bit的80386，所以ucore也要是32位的软件。  
-gstabs  生成stabs格式的调试信息。这样要ucore的monitor可以显示出便于开发者阅读的函数调用栈信息
-nostdinc  不使用标准库。标准库是给应用程序用的，我们是编译ucore内核，OS内核是提供服务的，所以所有的服务要自给自足。  
-fno-stack-protector  不生成用于检测缓冲区溢出的代码。这是for 应用程序的，我们是编译内核，ucore内核好像还用不到此功能。  
-Os  为减小代码大小而进行优化。根据硬件spec，主引导扇区只有512字节，我们写的简单bootloader的最终大小不能大于510字节。    
-I `<dir>`添加搜索头文件的路径

3、生成`bootmain.o`需要`bootmain.c`
```c
gcc -Iboot/ -fno-builtin -Wall -ggdb -m32 -gstabs -nostdinc  -fno-stack-protector -Ilibs/ -Os -nostdinc -c boot/bootmain.c -o obj/boot/bootmain.o
```
>-fno-builtin除非用__builtin_前缀，否则不进行builtin函数的优化

4、生成`bin/sign`
代码为
```c
$(call add_files_host,tools/sign.c,sign,sign)
$(call create_target_host,sign,sign)
```
实际的命令
```c
gcc -Itools/ -g -Wall -O2 -c tools/sign.c -o obj/sign/tools/sign.o
gcc -g -Wall -O2 obj/sign/tools/sign.o -o bin/sign
```
最终生成bootblock的命令为
```
ld -m    elf_i386 -nostdlib -N -e start -Ttext 0x7C00 obj/boot/bootasm.o obj/boot/bootmain.o -o obj/bootblock.o
```
其中参数为
```
-m <emulation>  模拟为i386上的连接器
-nostdlib  不使用标准库
-N  设置代码段和数据段均可读写
-e <entry>  指定入口
-Ttext  制定代码段开始位置
```
## 生成`bin/kernel`的相关代码
```
$(kernel): tools/kernel.ld
$(kernel): $(KOBJS)
    @echo "bbbbbbbbbbbbbbbbbbbbbb$(KOBJS)"
    @echo + ld $@
    $(V)$(LD) $(LDFLAGS) -T tools/kernel.ld -o $@ $(KOBJS)
    @$(OBJDUMP) -S $@ > $(call asmfile,kernel)
    @$(OBJDUMP) -t $@ | $(SED) '1,/SYMBOL TABLE/d; s/ .* / /; /^$$/d' > $(call symfile,kernel)

```
通过`make "V="`指令得到执行命令
```
ld -m    elf_i386 -nostdlib -T tools/kernel.ld -o bin/kernel  obj/kern/init/init.o obj/kern/libs/readline.o obj/kern/libs/stdio.o obj/kern/debug/kdebug.o obj/kern/debug/kmonitor.o obj/kern/debug/panic.o obj/kern/driver/clock.o obj/kern/driver/console.o obj/kern/driver/intr.o obj/kern/driver/picirq.o obj/kern/trap/trap.o obj/kern/trap/trapentry.o obj/kern/trap/vectors.o obj/kern/mm/pmm.o  obj/libs/printfmt.o obj/libs/string.o
```
新参数
>-T `<scriptfile>` 让连接器使用指定的脚本

最后看看ucore.img的生成过程  
1、生成有10000块的文件
```
dd if=/dev/zero of=bin/ucore.img count=10000
```
2、把`bootblock`中的内容写到第一个块
```
dd if=bin/bootblock of=bin/ucore.img conv=notrunc
```
3、`kernel`中的内容从第二个块开始写
```
dd if=bin/kernel of=bin/ucore.img seek=1 conv=notrunc
```
## 练习1.2 一个被系统认为是符合规范的硬盘主引导扇区的特征是什么?
1、引导扇区有512字节  
2、最后两字节为0x55AA

## 练习2 使用qemu执行并调试lab1中的软件
## 练习2.1 从 CPU 加电后执行的第一条指令开始,单步跟踪 BIOS 的执行

 修改`lab1/tools/gdbinit`文件为

```c
target remote :1234
set architecture i8086
```
并在lab1下执行`make debug`，会弹出一个`qemu`窗口和`gdb`调试窗口，输入`si`就可以一步一步跟踪BIOS  
***注意：调试的代码地址采用段存储机制，需要进行偏移***  
![](https://github.com/Juiceff/ucore_picture/blob/master/lab1/1.png)
## 练习2.2 在初始化位置0x7c00设置实地址断点,测试断点正常
修改`lab1/tools/gdbinit`文件为
```c
file bin/kernel
target remote :1234
set architecture i8086
b *0x7c02
continue
x /2i $pc
```
* 第一行指定文件
* 第二行与qemu建立来连接并指定1234端口
* 第三行设定为16位实模式
* 第四行b代表break设置断点为*0x7c02
* 第六行 x代表显示 i代表指令 $pc代表寄存器
并在lab1下执行`make debug`，便可得到如下结果：
![](https://github.com/Juiceff/ucore_picture/blob/master/lab1/2.png)
## 练习2.3 从0x7c00开始跟踪代码运行,将单步跟踪反汇编得到的代码与`bootasm.S`和`bootblock.asm`进行比较
跟踪代码如下：
```c
0x7c02:xor %eax,%eax
0x7c04:mov %eax,%ds
0x7c06:mov %eax,%es
0x7c08:mov %eax,%ss
0x7c0a:in  $0x64,%al
0x7c0c:test $0x2,%al
0x7c0e:jne  0x7c0a
0x7c10:mov  $0xd1,%al
0x7c12:out %al,$0x64
```
与`bootasm.S`和`bootblock.asm`对比后发现一致
## 练习3 分析bootloader进入保护模式的过程
1、将各个寄存器置0
```py
.code16               # Assemble for 16-bit mode
    cli                # Disable interrupts
    cld               # String operations increment
    # Set up the important data segment registers (DS, ES, SS).
    xorw %ax, %ax      # Segment number zero
    movw %ax, %ds     # -> Data Segment
    movw %ax, %es     # -> Extra Segment
    movw %ax, %ss      # -> Stack Segment
```
2、开启A20,为何开启？

```py
seta20.1:
    inb $0x64, %al    # 读取状态寄存器,等待8042键盘控制器闲置
    testb $0x2, %al   # 判断输入缓存是否为空
    jnz seta20.1

    movb $0xd1, %al    # 0xd1表示写输出端口命令，参数随后通过0x60端口写入
    outb %al, $0x64   

seta20.2:
    inb $0x64, %al    
    testb $0x2, %al
    jnz seta20.2

    movb $0xdf, %al   # 通过0x60写入数据11011111 即将A20置1
    outb %al, $0x60   
```
3、初始化GDT表
```
lgdt gdtdesc
```
4、进入保护模式
```
movl %cr0, %eax
    orl $CR0_PE_ON, %eax
    movl %eax, %cr0
```
5、通过长跳转更新cs的基地址
```py
 ljmp $PROT_MODE_CSEG, $protcseg
.code32
protcseg:
```
6、设置不同的段寄存器
```py
movw $PROT_MODE_DSEG, %ax
movw %ax, %ds
movw %ax, %es
movw %ax, %fs
movw %ax, %gs
movw %ax, %ss
movl $0x0, %ebp
movl $start, %esp
```
7、进入保护模式
```
call bootmain
```
## 练习4 分析bootloader加载ELF格式的OS的过程
1、查看函数`readsect(void *dst, uint32_t secno)`,从设备的第secno扇区读取数据到dst位置:
```c
readsect(void *dst, uint32_t secno) {
    // wait for disk to be ready
    waitdisk();

    outb(0x1F2, 1);                         // count = 1
    outb(0x1F3, secno & 0xFF);
    outb(0x1F4, (secno >> 8) & 0xFF);
    outb(0x1F5, (secno >> 16) & 0xFF);
    outb(0x1F6, ((secno >> 24) & 0xF) | 0xE0);
    outb(0x1F7, 0x20);                      // cmd 0x20 - read sectors

    // wait for disk to be ready
    waitdisk();

    // read a sector
    insl(0x1F0, dst, SECTSIZE / 4);
}
```
2、`readseg(uintptr_t va, uint32_t count, uint32_t offset)`简单包装了`readsect`，可以从设备读取任意长度的内容
```c
readseg(uintptr_t va, uint32_t count, uint32_t offset) {
    uintptr_t end_va = va + count;

    // round down to sector boundary
    va -= offset % SECTSIZE;

    // translate from bytes to sectors; kernel starts at sector 1
    uint32_t secno = (offset / SECTSIZE) + 1;

    // If this is too slow, we could read lots of sectors at a time.
    // We'd write more to memory than asked, but it doesn't matter --
    // we load in increasing order.
    for (; va < end_va; va += SECTSIZE, secno ++) {
        readsect((void *)va, secno);
    }
}
```
3、解释函数`bootmain(void)`
```c
bootmain(void) {
    // 读取ELF的头部
    readseg((uintptr_t)ELFHDR, SECTSIZE * 8, 0);

    // 通过储存在头部的幻数判断是否是合法的ELF文件
    if (ELFHDR->e_magic != ELF_MAGIC) {
        goto bad;
    }

    struct proghdr *ph, *eph;

    // ELF头部有描述ELF文件应加载到内存什么位置的描述表，先将描述表的头地址存在ph
    ph = (struct proghdr *)((uintptr_t)ELFHDR + ELFHDR->e_phoff);
    eph = ph + ELFHDR->e_phnum;
    for (; ph < eph; ph ++) {
        readseg(ph->p_va & 0xFFFFFF, ph->p_memsz, ph->p_offset);
    }

    // call the entry point from the ELF header
    // note: does not return
    // 根据ELF头部储存的入口信息，找到内核的入口
    ((void (*)(void))(ELFHDR->e_entry & 0xFFFFFF))();

bad:
    outw(0x8A00, 0x8A00);
    outw(0x8A00, 0x8E00);

    /* do nothing */
    while (1);
}
```
## 练习5 实现函数调用堆栈跟踪函数 我们需要在lab1中完成`kdebug.c`中函数`print_stackframe`的实现
参见kdebug.c代码中的注释：
```c
void print_stackframe(void) {
     /* LAB1 YOUR CODE : STEP 1 */
     /* (1) call read_ebp() to get the value of ebp. the type is (uint32_t);
      * (2) call read_eip() to get the value of eip. the type is (uint32_t);
      * (3) from 0 .. STACKFRAME_DEPTH
      *    (3.1) printf value of ebp, eip
      *    (3.2) (uint32_t)calling arguments [0..4] = the contents in address (unit32_t)ebp +2 [0..4]
      *    (3.3) cprintf("\n");
      *    (3.4) call print_debuginfo(eip-1) to print the C calling function name and line number, etc.
      *    (3.5) popup a calling stackframe
      *           NOTICE: the calling funciton's return addr eip  = ss:[ebp+4]
      *                   the calling funciton's ebp = ss:[ebp]
      */
}
```
根据注释，编写代码如下：
```c
void print_stackframe(void) {      
    uint32_t ebp=read_ebp();//(1) call read_ebp() to get the value of ebp. the type is (uint32_t)
    uint32_t eip=read_eip();//(2) call read_eip() to get the value of eip. the type is (uint32_t)
    int i;
    for(i=0;i<STACKFRAME_DEPTH&&ebp!=0;i++){//(3) from 0 .. STACKFRAME_DEPTH
          cprintf("ebp:0x%08x   eip:0x%08x ",ebp,eip);//(3.1)printf value of ebp, eip
          uint32_t *tmp=(uint32_t *)ebp+2;
          cprintf("arg :0x%08x 0x%08x 0x%08x 0x%08x",*(tmp+0),*(tmp+1),*(tmp+2),*(tmp+3));//(3.2)(uint32_t)calling arguments [0..4] = the contents in address (unit32_t)ebp +2 [0..4]
          cprintf("\n");//(3.3) cprintf("\n");
          print_debuginfo(eip-1);//(3.4) call print_debuginfo(eip-1) to print the C calling function name and line number, etc.
          eip=((uint32_t *)ebp)[1];
          ebp=((uint32_t *)ebp)[0];//(3.5) popup a calling stackframe
      }
}
```
![](https://github.com/Juiceff/ucore_picture/blob/master/lab1/3.png)
## 练习6 完善中断初始化和处理
## 练习6.1 中断向量表中一个表项占多少字节？其中哪几位代表中断处理代码的入口？
中断向量表一个表项占用8字节，其中2-3字节是段选择子，0-1字节和6-7字节拼成位移，
两者联合便是中断处理程序的入口地址
## 练习6.2 请编程完善kern/trap/trap.c中对中断向量表进行初始化的函数idt_init。在idt_init函数中，依次对所有中断入口进行初始化。使用mmu.h中的SETGATE宏，填充idt数组内容。每个中断的入口由tools/vectors.c生成，使用trap.c中声明的vectors数组即可
可以看到函数的注释如下：
```c
void idt_init(void) {
     /* LAB1 YOUR CODE : STEP 2 */
     /* (1) Where are the entry addrs of each Interrupt Service Routine (ISR)?
      *     All ISR's entry addrs are stored in __vectors. where is uintptr_t __vectors[] ?
      *     __vectors[] is in kern/trap/vector.S which is produced by tools/vector.c
      *     (try "make" command in lab1, then you will find vector.S in kern/trap DIR)
      *     You can use  "extern uintptr_t __vectors[];" to define this extern variable which will be used later.
      * (2) Now you should setup the entries of ISR in Interrupt Description Table (IDT).
      *     Can you see idt[256] in this file? Yes, it's IDT! you can use SETGATE macro to setup each item of IDT
      * (3) After setup the contents of IDT, you will let CPU know where is the IDT by using 'lidt' instruction.
      *     You don't know the meaning of this instruction? just google it! and check the libs/x86.h to know more.
      *     Notice: the argument of lidt is idt_pd. try to find it!
      */
}
```
根据注释编写程序：  
1、声明__vertors[],其中存放着中断服务程序的入口地址。这个数组生成于vertor.S中  
2、填充中断描述符表IDT  
3、加载中断描述符表
```c
void idt_init(void) {
    extern uintptr_t __vectors[];//声明__vertors[]
    int i;
    for(i=0;i<256;i++) {
        SETGATE(idt[i],0,GD_KTEXT,__vectors[i],DPL_KERNEL);
    }
    SETGATE(idt[T_SWITCH_TOK],0,GD_KTEXT,__vectors[T_SWITCH_TOK],DPL_USER);
    lidt(&idt_pd);//使用lidt指令加载中断描述符表
}
```
打开`kern/mm/mmu.h`查看`SETGATE`定义
```c
#define SETGATE(gate, istrap, sel, off, dpl) {  
    (gate).gd_off_15_0 = (uint32_t)(off) & 0xffff;
    (gate).gd_ss = (sel);             
    (gate).gd_args = 0;               
    (gate).gd_rsv1 = 0;               
    (gate).gd_type = (istrap) ? STS_TG32 : STS_IG32;
    (gate).gd_s = 0;               
    (gate).gd_dpl = (dpl);           
    (gate).gd_p = 1;               
    (gate).gd_off_31_16 = (uint32_t)(off) >> 16; 
}
```
## 练习6.3 请编程完善trap.c中的中断处理函数trap，在对时钟中断进行处理的部分填写trap函数中处理时钟中断的部分，使操作系统每遇到100次时钟中断后，调用print_ticks子程序，向屏幕上打印一行文字”100 hahaha”
查看`trap`函数，发现其调用了函数`trap_dispatch`，截取前半段：
```c
trap_dispatch(struct trapframe *tf) {
    char c;
    switch (tf->tf_trapno) {
    case IRQ_OFFSET + IRQ_TIMER:
        /* LAB1 YOUR CODE : STEP 3 */
        /* handle the timer interrupt */
        /* (1) After a timer interrupt, you should record this event using a global variable (increase it), such as ticks in kern/driver/clock.c
         * (2) Every TICK_NUM cycle, you can print some info using a funciton, such as print_ticks().
         * (3) Too Simple? Yes, I think so!
         */
        break;
    case IRQ_OFFSET + IRQ_COM1:
        c = cons_getc();
        cprintf("serial [%03d] %c\n", c, c);
        break;
```
根据注释编写程序实现隔100次时钟中断输出函数`print_ticks()`:
```c
ticks ++;
        if (ticks % TICK_NUM == 0)//TICK_NUM定义为100
        {
            print_ticks();
        }
```
在lab1目录下输入`make qemu`命令
![](https://github.com/Juiceff/ucore_picture/blob/master/lab1/4.png)
