# PlayStation 4 해킹 (9기)

## 1. 주제 소개

Jailbreak(탈옥) : 프로그램의 취약점을 이용하여 높은 권한을 획득하여 기존의 서비스에서는 사용할 수 없는 기능을 사용할 수 있게 되는 것  
PS4를 대상으로 Jailbreak를 시도하는 프로젝트라고 할 수 있다  

## 2. 주제 선정 이유

BoB 프로젝트 중 포너블 관련 연구들을 찾다가 BoB 9기에서 진행한 Playstation 4 해킹이라는 프로젝트를 발견하게 되어 탐구하기로 결정했다  
관련 자료들을 찾던 중 Playstation 4 해킹 프로젝트를 진행한 관련 문서를 발견하여 이를 참고해 글을 쓰게 되었다

## 3. 탐구하려는 주제에 대한 결과물 정리

# 3.1 Hacking the PS4 (Author : CTrut)
출처 : https://cturt.github.io/ps4.html  

관련 자료를 탐색하던 중, CTurt가 작성한 구버전 PS4 대상으로 Webkit 취약점과 Kernel 취약점을 포팅해 Exploit한 문서를 발견하였다  

위 문서의 주요 내용을 정리하면 다음과 같다 :  
* 1. PS4 펌웨어 1.76에서 인터넷 브라우저를 통해 커널 코드 실행까지 도달하는 전체 익스플로잇 체인
* 2. WebKit의 CVE-2012-3748 취약점(JSArray::sort 메서드의 힙 버퍼 오버플로우)을 이용해 브라우저 프로세스 제어
* 3. DEP를 우회하기 위해 ROP 사용, JavaScript로 ASLR 우회
* 4. FreeBSD 9.0 기반의 Orbis OS 분석, 시스템 콜 탐색 및 85개의 소니 커스텀 시스템 콜 발견
* 5. 시스템 콜 592/593을 통해 추가 모듈을 로드하고 덤프하여 분석
* 6. FreeBSD jail 기반 샌드박스가 파일시스템 접근과 시스템 콜 실행을 제한
* 7. getlogin 시스템 콜(CVE-2014-8476)을 통해 17바이트의 커널 메모리 누출 성공
* 8. 브라우저가 root 권한으로 실행되며, 커널 ASLR이 비활성화되어 있음을 확인

# 3.2 This is for the Pwners: Exploiting a WebKit 0-day in PlayStation 4 (Author : Mehdi Talbi, Quentin Meffre)
출처 : https://www.synacktiv.com/publications/this-is-for-the-pwners-exploiting-a-webkit-0-day-in-playstation-4.html  

또한, 2020년도 Black hat 컨퍼런스에서 발표된 PS4 0-Day exploit 관련 문서에 대해서도 소개하고자 한다  
BoB 프로젝트에선 1-Day 취약점 탐색을 목표로 진행하였으나, 이 문서는 0-Day를 연구해서 exploit을 진행하였다  

위 문서의 주요 내용을 정리하면 다음과 같다 :  
* 1. 취약점 개요: WebCore::ValidationMessage::buildBubbleTree 메서드의 Use-After-Free(UAF) 취약점으로,  
     레이아웃 업데이트 중 약한 포인터 생성 시 추가 역참조로 인해 객체가 조기 파괴될 수 있음
* 2. 트리거 방법:  
    reportValidity()로 ValidationMessage 생성  
    → 타이머 만료 전 포커스 이벤트 핸들러 등록  
    → 레이아웃 업데이트 중 JS 콜백에서 객체 파괴  
    → **UAF 발생**    
* 3. ASLR 우회: 힙 스프레이로 예측 가능한 위치에 HTMLElement 객체 할당 후 ValidationMessage을 ArrayBuffer로 교체하고 m_bubble/m_element를 고정 주소로 조작  

* 4. 익스플로잇 단계:
  - 객체 재사용: ValidationMessage 주변을 같은 크기 객체로 스프레이 → 해제 후 ArrayBuffer(48)로 재스프레이
  - 초기 메모리 릭: m_timer 값 유출로 같은 smallPage의 객체 주소 추론
  - 임의 감소 프리미티브: deleteBubbleTree의 refcount 감소를 악용해 StringImpl 길이 필드 조작  

## 4. 주제를 조사하고 난 이후 느낀점
주제에 대해 탐구하기 전엔 Playstation 4가 어떤 식으로 해킹이 이루어지는지 궁금했는데,  
PS4 또한 WebKit기반의 browser를 사용하고, FreeBSD 9 기반의 OS인 Orbis OS를 사용한다는 것을 활용하여  
브라우저의 취약점과 커널의 취약점을 chaining하여 Jailbreak가 이루어진다는 점이 인상깊었다
