# The Attack and Defense of Computers

本 Repo 記錄了「電腦攻防」課程中兩個 CTF 專題的解題過程與技術說明。

---

## 目錄

- [Project 1 – Binary Exploitation (Pwn)](#project-1--binary-exploitation-pwn)
- [Project 2 – Web Security](#project-2--web-security)

---

## Project 1 – Binary Exploitation (Pwn)

> 📄 詳細解題過程：[CTF-Project1.md](./CTF-Project1.md)

針對二進位程式的漏洞分析與利用，使用工具包含 IDA Pro、pwndbg、ROPgadget 及 pwntools。

| 題目 | 技術類型 | 說明 |
|------|----------|------|
| **helloworld** | Linux Shell 指令執行 | 識別 Shell 提示符並直接執行 Linux 指令取得 flag |
| **helloworld_again** | Buffer Overflow + Return Address Hijacking | 利用 `\x00` 截斷字串繞過長度與內容檢查，覆蓋返回位址 |
| **shellcode** | Shellcode Injection | 直接將 shellcode 注入 buffer，觸發 `execve(/bin/sh)` |
| **shellcodeplus** | Shellcode Injection（帶限制） | 在 byte-level 限制下構造符合條件的前置 pattern 並附加 shellcode |
| **gadgethunter** | ROP Chain (Return-Oriented Programming) | 利用緩衝區溢位構建 ROP chain，組合 gadget 呼叫 `execve("/bin/sh", NULL, NULL)` |
| **doors** | GOT Hijacking / RCE | 透過任意位址寫入竄改 puts 的 GOT entry，劫持執行流程跳至後門函式 |

---

## Project 2 – Web Security

> 📄 詳細解題過程：[CTF-Project2.md](./CTF-Project2.md)

針對 Web 應用程式的漏洞分析與利用，使用工具包含 Burp Suite、sqlmap、Python requests 及 webhook.site。

| 題目 | 技術類型 | 說明 |
|------|----------|------|
| **chiikawa_login_1** | SQL Injection（黑名單繞過） | 使用字詞重疊技巧（如 `UUNIONNION`）繞過 `str_ireplace` 黑名單，以 UNION SELECT 偽造登入 |
| **chiikawa_login_2** | Blind SQL Injection | 逐字元比對密碼，透過 `SUBSTRING` + `UNION SELECT` 爆出真實密碼 |
| **koduckkoduck** | Cookie 操作 / Base64 解碼 | 從 HTML 原始碼及 Set-Cookie 標頭中發現 Base64 編碼資訊，解碼取得 flag |
| **Subscribe** | HTTP 標頭偽造 + 暴力破解 | 逐步修改 Method、User-Agent、Referer、Host、Cookie 及 Basic Auth，以自製 Python 腳本暴力破解密碼 |
| **msg_board** | Stored XSS + Cookie Theft | 注入含 `onerror` 的 `<image>` 標籤，透過 `fetch` 將管理員 Cookie 送往 webhook.site |
| **Pokedex** | Command Injection | 利用 `$()` 子命令注入，繞過黑名單以 `tac`、`f[l]ag` 等變形讀取 flag 檔案 |

---

## 使用技術與工具

- **逆向分析**：IDA Pro、objdump
- **動態分析**：pwndbg、checksec
- **Exploit 開發**：[pwntools](https://github.com/Gallopsled/pwntools)、ROPgadget
- **Web 測試**：Burp Suite、sqlmap
- **輔助服務**：[webhook.site](https://webhook.site)
