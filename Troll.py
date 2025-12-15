import os
import sys
import subprocess

try:
    from Crypto.Cipher import AES
except ImportError:
    print("[*] Missing dependency detected. Installing pycryptodome...")
    subprocess.check_call([sys.executable, "-m", "pip", "install", "pycryptodome"])
    from Crypto.Cipher import AES
    print("[+] pycryptodome installed successfully.")

import time
import base64
import zlib
import lzma
import secrets
import hashlib
import string

BANNER = '''
     ▄▄▄▄▀▀▀▀▀▀▀▀▄▄▄▄▄▄
    █░░░░▒▒▒▒▒▒▒▒▒▒▒▒░░▀▀▄
   █░░░▒▒▒▒▒▒░░░░░░░░▒▒▒░░█
  █░░░░░░▄██▀▄▄░░░░░▄▄▄░░░█
 █▒▄▄▄▒░█▀▀▀▀▄▄█░░░██▄▄█░░░█
█▒█▒▄░▀▄▄▄▀░░░░░░░░█░░░▒▒▒▒▒█                                            
█▒█░█▀▄▄░░░░░█▀░░░░▀▄░░▄▀▀▀▄▒█     Github : https://github.com/ALMASONYH
 █▀▄░█▄░█▀▄▄░▀░▀▀░▄▄▀░░░░█░░█
  █░░▀▄▀█▄▄░█▀▀▀▄▄▄▄▀▀█▀██░░█     Discord Server : https://discord.gg/uCwQuJK  
   █░░██░░▀█▄▄▄█▄▄█▄████░░░█
   █░░░▀▀▄░█░░░█░███████░░█
    ▀▄░░░▀▀▄▄▄█▄█▄█▄█▄▀░░░█
      ▀▄▄░▒▒▒▒░░░░░░░░░░░█
        ▀▄▄░▒▒▒▒▒▒▒▒▒▒░█
            ▀▄▄▄▄▄▄▄▄▄▄█

{Coloque seu arquivo no mesmo caminho da ferramenta}
'''

def enc_layer(data, key):
    nonce = secrets.token_bytes(12)
    cipher = AES.new(key, AES.MODE_GCM, nonce=nonce)
    ciphertext, tag = cipher.encrypt_and_digest(data)
    return nonce, tag, ciphertext

def build_inner_loader(ciphertext, nonce, tag, size, a1, x1):
    ct_b64 = base64.b64encode(ciphertext).decode("ascii")
    n_hex = nonce.hex()
    tg_hex = tag.hex()
    
    return f'''import base64,zlib,hashlib,sys,os
from Crypto.Cipher import AES
def _d():
    import sys,os
    if sys.gettrace() is not None:
        sys.exit(0)
    _m=[]
    _m.append(bytes.fromhex("707964657664").decode())
    _m.append(bytes.fromhex("706462").decode())
    _m.append(bytes.fromhex("626462").decode())
    _m.append(bytes.fromhex("77696e617070646267").decode())
    _m.append(bytes.fromhex("676462").decode())
    for __x in _m:
        if __x in sys.modules:
            sys.exit(0)
_d()
L={size}
A={a1}
X={x1}
s=((L*A)^X).to_bytes(8, 'big')
b=b""
t=s
while len(b)<(L*2):
    t=hashlib.sha512(t).digest()
    b+=t
b=b[:L]
k=hashlib.sha256(b).digest()
c=base64.b64decode("{ct_b64}")
n=bytes.fromhex("{n_hex}")
g=bytes.fromhex("{tg_hex}")
x=AES.new(k,AES.MODE_GCM,nonce=n)
d=x.decrypt_and_verify(c,g)
d=zlib.decompress(d)
k1=bytes.fromhex("5f5f6e616d655f5f").decode()
k2=bytes.fromhex("5f5f6d61696e5f5f").decode()
h={{k1:k2}}
exec(d,h)
'''

def build_outer_loader(ciphertext, nonce, tag, size, a2, x2):
    ct_b64 = base64.b64encode(ciphertext).decode("ascii")
    n_hex = nonce.hex()
    tg_hex = tag.hex()
    
    return f'''import base64,zlib,hashlib,sys,os
from Crypto.Cipher import AES
def _d():
    import sys,os
    if sys.gettrace() is not None:
        sys.exit(0)
    _m=[]
    _m.append(bytes.fromhex("707964657664").decode())
    _m.append(bytes.fromhex("706462").decode())
    _m.append(bytes.fromhex("626462").decode())
    _m.append(bytes.fromhex("77696e617070646267").decode())
    _m.append(bytes.fromhex("676462").decode())
    for __x in _m:
        if __x in sys.modules:
            sys.exit(0)
_d()
L={size}
A={a2}
X={x2}
u=((L*A)^X).to_bytes(8, 'big')
q=b""
w=u
while len(q)<(L*2):
    w=hashlib.sha512(w).digest()
    q+=w
q=q[:L]
k=hashlib.sha256(q).digest()
c=base64.b64decode("{ct_b64}")
n=bytes.fromhex("{n_hex}")
g=bytes.fromhex("{tg_hex}")
a=AES.new(k,AES.MODE_GCM,nonce=n)
r=a.decrypt_and_verify(c,g)
r=zlib.decompress(r)
e={{"__name__":"__loader__"}}
exec(r,e)
'''

def random_name():
    first = secrets.choice(string.ascii_letters)
    rest = "".join(secrets.choice(string.ascii_letters + string.digits) for _ in range(7))
    return first + rest

def build_stub(hex_body, digest, size):
    h_hex_ascii = digest.encode().hex()
    s_hex_ascii = hex_body.encode().hex()
    main_key_hex = "__name__".encode().hex()
    main_val_hex = "__main__".encode().hex()

    v_hash = random_name()
    v_str = random_name()
    v_len = random_name()
    v_src = random_name()
    v_code = random_name()
    v_ns = random_name()
    v_fn = random_name()
    v_modlist = random_name()
    v_k1 = random_name()
    v_k2 = random_name()

    dict_line = "{" + f"{v_k1}:{v_k2}" + "}"

    stub = (
        f"import sys,hashlib,os\n"
        f"{v_hash}=bytes.fromhex('{h_hex_ascii}').decode()\n"
        f"{v_str}=bytes.fromhex('{s_hex_ascii}').decode()\n"
        f"def {v_fn}():\n"
        f"    import sys,os\n"
        f"    if sys.gettrace() is not None:\n"
        f"        sys.exit(0)\n"
        f"    {v_modlist}=[]\n"
        f"    {v_modlist}.append(bytes.fromhex('707964657664').decode())\n"
        f"    {v_modlist}.append(bytes.fromhex('706462').decode())\n"
        f"    {v_modlist}.append(bytes.fromhex('626462').decode())\n"
        f"    {v_modlist}.append(bytes.fromhex('77696e617070646267').decode())\n"
        f"    {v_modlist}.append(bytes.fromhex('676462').decode())\n"
        f"    for __m in {v_modlist}:\n"
        f"        if __m in sys.modules:\n"
        f"            sys.exit(0)\n"
        f"{v_fn}()\n"
        f"if hashlib.sha256({v_str}.encode()).hexdigest()!={v_hash}:\n"
        f"    sys.exit(0)\n"
        f"{v_len}={size}\n"
        f"{v_src}=bytes.fromhex({v_str})\n"
        f"{v_code}={v_src}.decode('utf-8')\n"
        f"{v_k1}=bytes.fromhex('{main_key_hex}').decode()\n"
        f"{v_k2}=bytes.fromhex('{main_val_hex}').decode()\n"
        f"{v_ns}={dict_line}\n"
        f"exec({v_code},{v_ns})\n"
    )
    return stub

def protect(path):
    with open(path, "rb") as f:
        raw = f.read()
    L = len(raw)

    a1 = secrets.randbits(16)
    x1 = secrets.randbits(32)
    a2 = secrets.randbits(16)
    x2 = secrets.randbits(32)
    
    s1 = ((L * a1) ^ x1).to_bytes(8, 'big')
    buf1 = b""
    t1 = s1
    while len(buf1) < (L * 2):
        t1 = hashlib.sha512(t1).digest()
        buf1 += t1
    buf1 = buf1[:L]
    k1 = hashlib.sha256(buf1).digest()

    comp1 = zlib.compress(raw, 9)
    n1, tg1, ct1 = enc_layer(comp1, k1)
    inner_code = build_inner_loader(ct1, n1, tg1, L, a1, x1)
    inner_bytes = inner_code.encode("utf-8")
    
    s2 = ((L * a2) ^ x2).to_bytes(8, 'big')
    buf2 = b""
    t2 = s2
    while len(buf2) < (L * 2):
        t2 = hashlib.sha512(t2).digest()
        buf2 += t2
    buf2 = buf2[:L]
    k2 = hashlib.sha256(buf2).digest()

    comp2 = zlib.compress(inner_bytes, 9)
    n2, tg2, ct2 = enc_layer(comp2, k2)
    outer_code = build_outer_loader(ct2, n2, tg2, L, a2, x2)

    outer_bytes = outer_code.encode("utf-8")
    hex_body = outer_bytes.hex()
    digest = hashlib.sha256(hex_body.encode()).hexdigest()
    stub_code = build_stub(hex_body, digest, L)

    stub_bytes = stub_code.encode('utf-8')
    compressed = zlib.compress(stub_bytes, 9)
    lzma_compressed = lzma.compress(compressed)
    b64_encoded = base64.b64encode(lzma_compressed).decode('ascii')
    
    def insert_marker(s, every=10):
        return "☭".join(s[i:i+every] for i in range(0, len(s), every))

    marked = insert_marker(b64_encoded, 10)
    
    parts = []
    part_length = len(marked) // 10
    
    for i in range(10):
        start = i * part_length
        end = (i + 1) * part_length if i < 9 else len(marked)
        parts.append(marked[start:end])
    
    var_names = [random_name() for _ in range(10)]
    var_parts = list(zip(var_names, parts))
    
    code_parts = []
    for var_name, part_content in var_parts:
        code_parts.append(f"{var_name}='{part_content}'")
    
    all_vars = [vn for vn, _ in var_parts]
    execution_code = "exec(zlib.decompress(lzma.decompress(base64.b64decode((" + "+".join(all_vars) + ").replace('☭','')))))"
    
    code_with_execution = []
    for part in code_parts:
        code_with_execution.append(part)
    
    code_with_execution.append(execution_code)
    
    final_loader = ';'.join(['import base64,lzma,zlib'] + code_with_execution)

    name, _ = os.path.splitext(path)
    out_path = name + "_protected.py"

    with open(out_path, "w", encoding="utf-8") as f:
        f.write(final_loader)

def main():
    print(BANNER)
    fn = input("FileName :").strip()
    if not fn:
        print("[!] Empty file name")
        return
    if not os.path.isfile(fn):
        return
    protect(fn)

if __name__ == "__main__":
    main()
