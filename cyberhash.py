#!/usr/bin/env python3
import hashlib
import base64
import argparse
import time
import os
import logging
from concurrent.futures import ThreadPoolExecutor
import shutil
import platform
import itertools
import string
import json
import signal
import sys
import zlib
from passlib.hash import nthash
from multiprocessing import Process, Queue
from rich.console import Console
from rich.progress import Progress
from rich.panel import Panel
from rich.table import Table
from rich.text import Text
from rich.align import Align
from pyfiglet import Figlet

console = Console()

# ========================= LOGGING =========================
if not os.path.exists("logs"):
    os.makedirs("logs")

logging.basicConfig(
    filename=f"logs/hashscan_{int(time.time())}.log",
    level=logging.INFO,
    format="%(asctime)s - %(message)s"
)
#======================SCREEN CLEAR===============================
def clear_terminal():
    print("\033[2J\033[H", end="")
#==================BANNER CENTER PLACING===================
def banner():

    fig = Figlet(font="slant")
    title = fig.renderText("CyberHash")

    # center ASCII banner using terminal width
    width = shutil.get_terminal_size().columns
    centered_title = "\n".join(line.center(width) for line in title.splitlines())

    console.print(f"[cyan]{centered_title}[/cyan]")

    panel_text = (
        "[bold yellow]Cyber Hash Analyzer v3.0[/bold yellow]\n"
        "[white]Professional Hash Analysis Utility[/white]"
    )

    console.print(
        Align.center(
            Panel(
                Align.center(panel_text),
                border_style="cyan",
                width=width - 10
            )
        )
    )


# ===================== ADVANCED ATTACK SYSTEMS =====================
# integrates: rule engine, mask attack, session resume, distributed cracking,
# automatic checkpoint saving, signal handling, mask presets


# ===================== GLOBAL SESSION STATE =====================

SESSION_FILE = "session.json"

CURRENT_INDEX = 0
CURRENT_WORDLIST = None
TARGET_HASH = None


# ===================== SESSION SAVE =====================

def save_session(index, wordlist_path, target_hash):

    data = {
        "index": index,
        "wordlist": wordlist_path,
        "hash": target_hash
    }

    with open(SESSION_FILE, "w") as f:
        json.dump(data, f)


# ===================== SESSION LOAD =====================

def load_session():

    if not os.path.exists(SESSION_FILE):
        return None

    with open(SESSION_FILE) as f:
        return json.load(f)


# ===================== INTERRUPT HANDLER =====================

def interrupt_handler(sig, frame):

    console.print("\n[yellow][*] Interrupt detected. Saving session...[/yellow]")

    save_session(CURRENT_INDEX, CURRENT_WORDLIST, TARGET_HASH)

    console.print("[green][+] Session saved[/green]")

    sys.exit(0)


signal.signal(signal.SIGINT, interrupt_handler)
signal.signal(signal.SIGTERM, interrupt_handler)

try:
    signal.signal(signal.SIGTSTP, interrupt_handler)
except:
    pass

#==================AUTOMATIC MULTI-ALGO ENGINE==============

def possible_algorithms(hash_value):
    l = len(hash_value)


    if l == 32:
        return ["MD5", "NTLM"]

    elif l == 40:
        return ["SHA1"]

    elif l == 56:
        return ["SHA224"]

    elif l == 64:
        return ["SHA256", "SHA3_256", "SHAKE256"]

    elif l == 96:
        return ["SHA384"]

    elif l == 128:
        return ["SHA512", "SHA3_512", "SHAKE256"]

    return []


def auto_check_word(word, target_hash, algos):
    data = word.encode()
    hlen = len(target_hash)

    for algo in algos:
        try:
            if compute_hash(data, algo, hlen) == target_hash:
                return (algo, word, "Auto", None)
        except:
            pass
    return None

def resolve_algorithms(args_algo, target_hash):
    if args_algo:
        return [args_algo]

    algos = possible_algorithms(target_hash)

    if not algos:
        console.print("[red]Unable to determine possible algorithms[/red]")
        sys.exit()

    console.print(f"[yellow][*] Possible algorithms:[/yellow] {', '.join(algos)}")

    return algos
# ===================== RULE ENGINE =====================

def apply_rules(word):

    rules = [
        lambda w: w.upper(),
        lambda w: w.capitalize(),
        lambda w: w + "1",
        lambda w: w + "123",
        lambda w: w + "2024",
        lambda w: "@" + w,
        lambda w: w + "!",
        lambda w: w.replace("a", "@"),
        lambda w: w.replace("o", "0"),
        lambda w: w.replace("e", "3")
    ]

    results = []

    for r in rules:
        try:
            results.append(r(word))
        except:
            pass

    return results


# ===================== EXTENDED WORD CHECK =====================

def extended_check_word(word, target_hash, algo):

    res = check_word(word, target_hash, algo)

    if res:
        return res

    for mutated in apply_rules(word):

        r = check_word(mutated, target_hash, algo)

        if r:
            return r

    return None


# ===================== MASK PRESETS =====================

MASK_PRESETS = {

    "simple_numeric": "?d?d?d?d",
    "common_password": "?l?l?l?l?d?d",
    "capital_word_number": "?u?l?l?l?l?d?d",
    "word_year": "?l?l?l?l?d?d?d?d",
    "admin_style": "admin?d?d"
}


# ===================== MASK SETS =====================

MASK_SETS = {

    "?l": string.ascii_lowercase,
    "?u": string.ascii_uppercase,
    "?d": string.digits,
    "?s": "!@#$%^&*"
}


# ===================== MASK GENERATOR =====================

def mask_attack(mask):

    parts = []

    i = 0

    while i < len(mask):

        if mask[i] == "?" and i + 1 < len(mask):

            token = mask[i:i+2]

            if token in MASK_SETS:

                parts.append(MASK_SETS[token])

                i += 2

                continue

        parts.append(mask[i])

        i += 1

    for combo in itertools.product(*parts):

        yield "".join(combo)


# ===================== MASK ATTACK RUNNER =====================

def run_mask_attack(mask, target_hash, algo):

    console.print(f"[yellow][*] Running mask attack: {mask}[/yellow]")

    start = time.time()

    tested = 0

    for candidate in mask_attack(mask):

        tested += 1

        if compute_hash(candidate.encode(), algo, len(target_hash)) == target_hash:

            result(candidate, algo, "Mask Attack", None, start, tested)

            return True

    console.print("[red][-] Mask attack failed[/red]")

    return False


# ===================== RESUME SCAN =====================

def resume_scan(wordlist_path, target_hash, algo):
    global CURRENT_INDEX
    global CURRENT_WORDLIST
    global TARGET_HASH
    CURRENT_WORDLIST = wordlist_path
    TARGET_HASH = target_hash
    session = load_session()
    start_index = 0
    if session and session.get("hash") == target_hash and session.get("wordlist") == wordlist_path:
        start_index = session.get("index", 0)
        console.print(f"[yellow][*] Resuming session from index {start_index}[/yellow]")
    start = time.time()
    tested = 0
    with open(wordlist_path, "r", errors="ignore") as f:
        for i, line in enumerate(f):
            if i < start_index:
                continue
            CURRENT_INDEX = i
            word = line.strip()
            if not word:
                continue
            res = extended_check_word(word, target_hash, algo)
            tested += 1
            if tested % 5000 == 0:
                save_session(CURRENT_INDEX, wordlist_path, target_hash)
            if res:
                method, w, shift = res
                result(w, algo, method, shift, start, tested)
                if os.path.exists(SESSION_FILE):
                    try:
                        os.remove(SESSION_FILE)
                    except:
                        pass
                return True
    return False
# ===================== DISTRIBUTED CRACKING =====================

def split_wordlist(file_path, workers):

    size = os.path.getsize(file_path)

    chunk = size // workers

    ranges = []

    start = 0

    for i in range(workers):

        end = start + chunk

        if i == workers - 1:
            end = size

        ranges.append((start, end))

        start = end

    return ranges


def process_chunk(file_path, start, end, target_hash, algo):

    with open(file_path, "r", errors="ignore") as f:

        f.seek(start)

        while f.tell() < end:

            word = f.readline().strip()

            res = extended_check_word(word, target_hash, algo)

            if res:
                return res

    return None


def distributed_attack(wordlist, target_hash, algo, workers):

    ranges = split_wordlist(wordlist, workers)

    queue = Queue()

    processes = []
    def worker(queue, wordlist, start, end, target_hash, algo):
        result = process_chunk(wordlist, start, end, target_hash, algo)
        queue.put(result)
    for start, end in ranges:
        p = Process(
            target=worker,
            args=(queue, wordlist, start, end, target_hash, algo)
)

        p.start()

        processes.append(p)

    for p in processes:
        p.join()

    while not queue.empty():

        res = queue.get()

        if res:
            return res

    return None
#=======================DETECTION ENGINE==========================
import re

HASH_SIGNATURES = [
    {"name": "bcrypt", "regex": r"^\$2[aby]\$\d+\$.*"},
    {"name": "sha512crypt", "regex": r"^\$6\$.*"},
    {"name": "sha256crypt", "regex": r"^\$5\$.*"},
    {"name": "md5crypt", "regex": r"^\$1\$.*"},
]

def identify_hash(hash_value):


# prefix / structure detection
    for sig in HASH_SIGNATURES:
        if re.match(sig["regex"], hash_value):
            return sig["name"].upper()

    # charset detection
    if re.fullmatch(r"[a-fA-F0-9]+", hash_value):

        length = len(hash_value)

        if length == 32:
            return "MD5 / NTLM"

        elif length == 40:
            return "SHA1"

        elif length == 56:
            return "SHA224"

        elif length == 64:
            return "SHA256"

        elif length == 96:
            return "SHA384"

        elif length == 128:
            return "SHA512"

    # base64 detection
    if re.fullmatch(r"[A-Za-z0-9+/=]+", hash_value):
        return "BASE64 ENCODED DATA"

    return "UNKNOWN"
# ========================= HASH DETECTION =========================
def detect_algorithm(hash_value):
    l = len(hash_value)
    if l == 32:
        return "MD5"
    elif l == 40:
        return "SHA1"
    elif l == 56:
        return "SHA224"
    elif l == 64:
        return "SHA256"
    elif l == 96:
        return "SHA384"
    elif l == 128:
        return "SHA512"
    return None
# ========================= HASH ENGINE =========================
def compute_hash(data, algo, hash_length=None):
    if algo == "MD5":
        return hashlib.md5(data).hexdigest()
    elif algo == "SHA1":
        return hashlib.sha1(data).hexdigest()
    elif algo == "SHA224":
        return hashlib.sha224(data).hexdigest()
    elif algo == "SHA256":
        return hashlib.sha256(data).hexdigest()
    elif algo == "SHA384":
        return hashlib.sha384(data).hexdigest()
    elif algo == "SHA512":
        return hashlib.sha512(data).hexdigest()
    elif algo == "SHA3_224":
        return hashlib.sha3_224(data).hexdigest()
    elif algo == "SHA3_256":
        return hashlib.sha3_256(data).hexdigest()
    elif algo == "SHA3_384":
        return hashlib.sha3_384(data).hexdigest()
    elif algo == "SHA3_512":
        return hashlib.sha3_512(data).hexdigest()
    elif algo == "SHA512_224":
        return hashlib.new("sha512_224", data).hexdigest()
    elif algo == "SHAKE256":
        if hash_length is None:
            hash_length = 64
        return hashlib.shake_256(data).hexdigest(hash_length // 2)
    elif algo == "SHAKE128":
        if hash_length is None:
            hash_length = 64
        return hashlib.shake_128(data).hexdigest(hash_length // 2)
    elif algo == "CRC32":
        return format(zlib.crc32(data) & 0xffffffff, "08x")  
    elif algo == "NTLM":
        return nthash.hash(data.decode())
    else:
        raise ValueError(f"Unsupported algorithm: {algo}")
# ========================= BASE64 =========================
def base64_hash(data, algo, hash_length):
    encoded = base64.b64encode(data)
    return compute_hash(encoded, algo, hash_length)
# ========================= ROT13 =========================
def rot13(data):
    result=[]
    for c in data.decode():
        if 'a'<=c<='z':
            result.append(chr((ord(c)-97+13)%26+97))
        elif 'A'<=c<='Z':
            result.append(chr((ord(c)-65+13)%26+65))
        else:
            result.append(c)
    return "".join(result).encode()

# ========================= CAESAR =========================
def caesar_variants(word):
    variants=[]
    for shift in range(1,26):
        out=[]
        for c in word.decode():
            if 'a'<=c<='z':
                out.append(chr((ord(c)-97+shift)%26+97))
            elif 'A'<=c<='Z':
                out.append(chr((ord(c)-65+shift)%26+65))
            else:
                out.append(c)
        variants.append((shift,"".join(out).encode()))
    return variants

# ========================= MUTATION ENGINE =========================
def mutations(word):
    w=word.decode()
    return [
        w.upper().encode(),
        w.capitalize().encode(),
        (w+"123").encode(),
        (w+"1234").encode(),
        (w+"2024").encode(),
        ("@"+w).encode(),
        (w+"!").encode()
    ]

# ========================= WORDLIST LOADER =========================
def load_wordlist(user_path=None):

    # 1 user supplied wordlist
    if user_path:
        if os.path.exists(user_path):
            console.print(f"[green][+] Using user wordlist:[/green] {user_path}")
            return user_path
        else:
            console.print("[red]User wordlist not found[/red]")
            exit()

    # 2 Linux system wordlist
    if platform.system() == "Linux":
        linux_paths = [
            "/usr/share/wordlists/rockyou.txt",
            "/usr/share/wordlists/fasttrack.txt"
        ]

        for p in linux_paths:
            if os.path.exists(p):
                console.print(f"[green][+] Using system wordlist:[/green] {p}")
                return p

    # 3 bundled fallback (works on ALL OS)
    fallback = "wordlists/default_wordlist.txt"

    if os.path.exists(fallback):
        console.print(f"[yellow][*] Using default tool wordlist:[/yellow] {fallback}")
        return fallback

    console.print("[red]No wordlist available[/red]")
    exit()
# ========================= WORD CHECK =========================
def check_word(word,target_hash,algo):

    data=word.encode()

    if compute_hash(data, algo, len(target_hash)) == target_hash:
        return ("Direct",word,None)

    if base64_hash(data,algo,len(target_hash))==target_hash:
        return ("Base64",word,None)

    r13=rot13(data)
    if compute_hash(r13,algo,len(target_hash))==target_hash:
        return ("ROT13",word,None)

    for shift,val in caesar_variants(data):
        if compute_hash(val,algo,len(target_hash))==target_hash:
            return ("Caesar",word,shift)

    for m in mutations(data):
        if compute_hash(m,algo,len(target_hash))==target_hash:
            return ("Mutation",m.decode(),None)

    return None

# ========================= RESULT =========================
def result(word,algo,method,shift,start,count):

    table=Table(title="HASH CRACK RESULT")
    table.add_column("Field",style="cyan")
    table.add_column("Value",style="green")

    table.add_row("Word",word)
    table.add_row("Algorithm",algo)
    table.add_row("Method",method)

    if shift:
        table.add_row("Shift",str(shift))

    table.add_row("Words Tested",str(count))
    table.add_row("Runtime",f"{time.time()-start:.2f}s")

    console.print(table)

# ========================= BENCHMARK =========================
def benchmark(algo):
    console.print("[yellow]Running benchmark...[/yellow]")
    test=b"benchmarkpassword"
    start=time.time()
    count=0
    while time.time()-start<3:
        compute_hash(test, algo, 64)
        count+=1
    speed=count/3
    console.print(f"[green]Speed:[/green] {int(speed)} H/s")
# ========================= MAIN ENGINE =========================
def main():
    global CURRENT_INDEX
    global CURRENT_WORDLIST
    global TARGET_HASH
    parser = argparse.ArgumentParser(description="Cyber Hash Analyzer")
    parser.add_argument("--hash", required=True, help="target hash")
    parser.add_argument("--threads", type=int, default=4)
    parser.add_argument("--wordlist", help="custom wordlist path")
    parser.add_argument("--benchmark", action="store_true")
    parser.add_argument("--mask", help="mask attack pattern")
    parser.add_argument("--resume", action="store_true", help="resume previous session")
    parser.add_argument("--distributed", type=int, help="number of distributed workers")
    parser.add_argument("--rules", action="store_true", help="enable rule engine")
    parser.add_argument("--algo", help="Manually specify algorithm")
    args = parser.parse_args()
    clear_terminal()
    banner()
    target_hash = args.hash.lower()
    fingerprint = identify_hash(target_hash)
    console.print(f"[cyan][*] Hash fingerprint:[/cyan] {fingerprint}")
    algo = resolve_algorithms(args.algo, target_hash)
    if not algo:
        console.print("[red]Unsupported hash type[/red]")
        return
    console.print(f"[yellow]Detected Algorithm:[/yellow] {', '.join(algo)}")
    wordlist_path = load_wordlist(args.wordlist)
    if args.benchmark:
        algorithm = resolve_algorithms(args.algo,target_hash)
        benchmark(algorithm[0])
    if args.mask:
        success = run_mask_attack(args.mask, target_hash, algo[0])
        if success:
            return
    if args.resume:
        success = resume_scan(wordlist_path, target_hash, algo[0])
        if success:
            return
    if args.distributed:
        console.print(f"[yellow][*] Distributed attack with {args.distributed} workers[/yellow]")
        res = distributed_attack(wordlist_path, target_hash, algo[0], args.distributed)
        if res:
            method, word, shift = res
            result(word, algo, method, shift, time.time(), 0)
            return
    start = time.time()
    tested = 0
    console.print("[blue][*] Starting scan[/blue]")
    with Progress() as progress:
        task = progress.add_task("Scanning", total=None)
        with open(wordlist_path, "r", errors="ignore") as f:
            with ThreadPoolExecutor(max_workers=args.threads) as executor:
                futures = []
                for i, line in enumerate(f):
                    word = line.strip()
                    if not word:
                        continue
                    CURRENT_INDEX = i
                    if args.rules:
                        futures.append(
                            executor.submit(extended_check_word, word, target_hash, algo)
                        )
                    else:
                        futures.append(
                            executor.submit(auto_check_word, word, target_hash, algo)
                        )
                    tested += 1
                    progress.update(task, advance=1)
                    if tested % 5000 == 0:
                        save_session(CURRENT_INDEX, wordlist_path, target_hash)
                    if len(futures) >= args.threads * 3:
                        for future in futures:
                            res = future.result()
                            if res:
                                algo, w, method, shift = res
                                logging.info(f"FOUND {w}")
                                result(w, algo, method, shift, start, tested)
                                if os.path.exists(SESSION_FILE):
                                    try:
                                        os.remove(SESSION_FILE)
                                    except:
                                        pass
                                return
                        futures = []
    console.print("[red][-] Hash not found[/red]")
    console.print(f"[yellow]Words tested:[/yellow] {tested}")
    console.print(f"[yellow]Time:[/yellow] {time.time()-start:.2f}s")
    logging.info("Hash not found")
# ========================= EXEC =========================
if __name__=="__main__":
    main()