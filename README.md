![unnamed](https://github.com/user-attachments/assets/da1413a3-ff0a-482c-8b8e-000625890da3)
# Psycho-bruteforcer
Built a multi-threaded, memory-efficient Python tool for testing login mechanisms in authorized lab environments. The project focuses on understanding authentication workflows, CSRF token handling, session management, rate-limiting defenses, and scalable request design using large wordlists.
# Important Features
1.✅ Automatic CSRF / Token Handling.

2.🌐 SOCKS5 Proxy Support.

3.🧬 User-Agent Rotation (Built-in default list & Custom User-Agent file support) to reduce detection.

4.🔁 Redirect Location Header Detection (Useful for identifying successful login attempts).

5.⚡ Multi-Threaded Engine.

6.🧠 Memory-Efficient Wordlist Processing.

Handles large files without loading them fully into RAM
# Example Of Usage
A basic Usage
```
python3 Psycho.py --url https://example.com/login.php \
    --user-field username \
    --pass-field password \
    --wordlist-target pass \
    --user admin \
    --passwords passwords.txt \
    --delay 0.5
```
# How To Install It
```
git clone https://github.com/mohamedessamibraahim-prog/Psycho-bruteforcer.git;
cd Psycho-bruteforcer;
python3 Psycho.py
```

⚠️Note: code is updated to improve the threads option.

THANKS.
