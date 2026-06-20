import math
import os
import re
import hashlib

RISKY_EXTENSIONS = {
    '.exe', '.bat', '.cmd', '.com', '.vbs', '.vbe', '.js', '.jse',
    '.wsf', '.wsh', '.ps1', '.ps2', '.pif', '.scr', '.msi', '.dll',
    '.jar', '.py', '.sh', '.rb', '.php', '.asp', '.aspx', '.lnk'
}

SUSPICIOUS_KEYWORDS = [
    b'encrypt', b'decrypt', b'ransom', b'bitcoin', b'wallet',
    b'payment', b'CryptoLocker', b'WannaCry', b'Locky',
    b'HKEY_LOCAL_MACHINE', b'reg add', b'regedit',
    b'cmd.exe', b'powershell', b'wscript', b'cscript',
    b'socket', b'connect', b'http://', b'https://',
    b'wget', b'curl', b'ftp://',
    b'DeleteFile', b'MoveFile', b'CopyFile', b'WriteFile',
    b'shadow', b'vssadmin', b'bcdedit', b'wbadmin',
    b'IsDebuggerPresent', b'anti-debug', b'sandbox',
]

def calculate_entropy(data):
    if not data:
        return 0.0
    freq = {}
    for byte in data:
        freq[byte] = freq.get(byte, 0) + 1
    entropy = 0.0
    total = len(data)
    for count in freq.values():
        p = count / total
        if p > 0:
            entropy -= p * math.log2(p)
    return round(entropy, 4)

def extract_strings(data, min_len=4):
    pattern = rb'[A-Za-z0-9/\-:.,_@!?(){}\[\]\'\" ]{' + str(min_len).encode() + rb',}'
    strings = re.findall(pattern, data)
    return [s.decode('ascii', errors='ignore') for s in strings]

def check_suspicious_strings(data):
    matched = []
    data_lower = data.lower()
    for kw in SUSPICIOUS_KEYWORDS:
        if kw.lower() in data_lower:
            matched.append(kw.decode('ascii', errors='ignore'))
    return len(matched) > 0, matched

def count_urls(strings):
    url_pattern = re.compile(r'https?://|ftp://', re.IGNORECASE)
    return sum(1 for s in strings if url_pattern.search(s))

def count_ips(strings):
    ip_pattern = re.compile(r'\b(?:\d{1,3}\.){3}\d{1,3}\b')
    return sum(1 for s in strings if ip_pattern.search(s))

def get_extension_risk(filename):
    ext = os.path.splitext(filename)[1].lower()
    return 1 if ext in RISKY_EXTENSIONS else 0

def get_file_hashes(data):
    return {
        "md5": hashlib.md5(data).hexdigest(),
        "sha256": hashlib.sha256(data).hexdigest(),
    }

def extract_features(file_path, original_filename):
    with open(file_path, 'rb') as f:
        data = f.read()

    file_size = len(data)
    entropy = calculate_entropy(data)
    has_sus, sus_list = check_suspicious_strings(data)
    ext_risk = get_extension_risk(original_filename)
    strings = extract_strings(data)
    url_count = count_urls(strings)
    ip_count = count_ips(strings)
    hashes = get_file_hashes(data)

    return {
        "features": [file_size, entropy, int(has_sus), ext_risk,
                     len(strings), url_count, ip_count],
        "file_size": file_size,
        "entropy": entropy,
        "has_sus_strings": has_sus,
        "suspicious_list": sus_list[:10],
        "extension_risk": ext_risk,
        "string_count": len(strings),
        "url_count": url_count,
        "ip_count": ip_count,
        "md5": hashes["md5"],
        "sha256": hashes["sha256"],
        "extension": os.path.splitext(original_filename)[1].lower() or "(none)",
    }