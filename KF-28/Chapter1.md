https://github.com/hspace-io/Space_Alone/blob/main/problems/Chapter01/ch1.c
```
int main()
{
    int cmp1 = 3, cmp2 = 3, cmp3 = 3, cmp4 = 3;
    char admin[10] = "deny", id_input[20], pw_input[20];

    system("clear");

    printf("ID: ");
    scanf("%s", id_input);
    printf("PASSWORD: ");
    scanf("%s", pw_input);
    sleep(1);
    if(strncmp(id_input, "admin", 5) == 0) printf("%s\n", admin);
    sleep(1);

    cmp1 = strncmp(id, id_input, 10);
    cmp2 = strncmp(pw, pw_input, 19);
    cmp3 = strncmp(id_input, "admin", 5);
    cmp4 = strncmp(admin, "confirm", 7);

    if(cmp1 == 0 && cmp2 == 0){
        printf("Wellcome Back!\n");
        menu();
        exit(0);
    }

    if(cmp3 == 0 && cmp4 == 0){
	system("clear");
        printf("Redirect to Admin page\n");

        sleep(1);
        printf(".......\n");
        sleep(1);
        printf(".......\n");
        sleep(1);
        printf(".......\n");
        sleep(1);
        printf(".......\n");
        sleep(1);
        printf(".......\n");

        system("clear");

        root();

        exit(0);
    }
    

    return 0;
}
```

간단하게 분석을 해보면 ID와 PW를 각각 id_input과 pw_input 변수에 입력받고 비교구문으로 넘어간다.  
비교구문으로 넘어가기 전에 입력을 scanf("%s", var);로 받기 때문에 입력에 길이 제한이 없다.  
즉, stack-based 버퍼 오버플로우가 가능하다.  

입력을 받은 후에는, strncmp로 id_input과 pw_input을 비교하여 cmp1, cmp2, cmp3, cmp4에 결과를 저장한다.  
이때, ``cmp3 == 0 && cmp4 == 0``을 만족하면 ``root()`` 함수가 실행된다.  
``root()`` 함수에 진입한 후, 2번 옵션을 선택하면 .TOP_SECRET 파일의 내용을 읽을 수 있게 된다.  

익스플로잇 과정을 생각해보면 다음과 같을 것이다:
```
1. [rbp-0x30]부터 ID를 입력받을 때, "deny" 문자열이 [rbp-0x1a]에 있으므로 A * 0x16 + "confirm" 문자열을 입력해 "deny" 문자열을 변조한다.

2. [rbp-0x50]부터 PW를 입력받을 때, A * 0x20 + "admin" 문자열을 입력해 ID를 다시 admin으로 바꾼다.

3. cmp3의 조건인 id_input == "admin"과 cmp4의 조건인 pw_input="confirm"을 통과하고 두 변수의 값은 0으로 바뀐다.

4. 이에 따라 root() 함수의 실행 조건을 만족하면서 read_file((char *)".TOP_SECRET");이 실행될 것이다.
```
익스플로잇을 짤 것도 없이 그냥 ID에 ``A * 0x16 + confirm``을 입력하고, PW에 ``A * 0x20 + admin``을 입력하면 ``root()``함수를 실행시킬 수 있다.  
메뉴에서 2번을 선택하면 .TOP_SECRET의 내용을 읽을 수 있다.  

```
Password for chapter2
# simple_bof
```

Chapter 2의 비밀번호를 알아냈으니 next 명령어를 사용하여 Chapter 2로 넘어가면 된다.
