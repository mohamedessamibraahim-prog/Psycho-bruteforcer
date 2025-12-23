# Psycho-bruteforcer
Built a multi-threaded, memory-efficient Python tool for testing login mechanisms in authorized lab environments. The project focuses on understanding authentication workflows, CSRF token handling, session management, rate-limiting defenses, and scalable request design using large wordlists.

# Example Of Usage
A basic Usage
```
python3 Psycho.py --url https://example.com/login.php \
    --user-field username
    --user-field password 
    --wordlist-target pass \
    --user admin \
    --passwords passwords.txt \
    --threads 10 \
    --delay 0.5
```
# How To Install It
```
git clone https://github.com/mohamedessamibraahim-prog/Psycho-bruteforcer.git;
cd Psycho-bruteforcer;
python3 Psycho.py
```
THANKS.
