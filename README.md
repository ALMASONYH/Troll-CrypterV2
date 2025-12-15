# Troll-Crypter V2
This project is a revival of a project I created in 2022     
The idea was to encrypt Python files and protect them from reverse engineering     
I took the same project and the same design and improved it so it can do encryption in a more "manual" and controlled way

![TrollCrypter](https://i.ibb.co/8n20tfdM/image.png)

The stub is divided into 3 stages:
---
First stage
```py
def build_inner_loader(ct: bytes, n: bytes, tg: bytes, size: int, a1: int, x1: int) -> str:
    ct_b64 = base64.b64encode(ct).decode("ascii")
    n_hex = n.hex()
    tg_hex = tg.hex()
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
s=str((L*A)^X).encode()
b=b""
t=s
while len(b)<L:
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
h={k1:k2}
exec(d,h)
'''
````

---

In the **first stage**, the loader creates a key from the file size and constants
It uses this key to decrypt and decompress the original Python code, then executes it

---

The second stage

```py
def build_outer_loader(ct: bytes, n: bytes, tg: bytes, size: int, a2: int, x2: int) -> str:
    ct_b64 = base64.b64encode(ct).decode("ascii")
    n_hex = n.hex()
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
u=str((L*A)^X).encode()
q=b""
w=u
while len(q)<L:
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
e={"__name__":"__loader__"}
exec(r,e)
'''
```

In the **second stage**, another key is generated with different constants
This stage decrypts and runs the inner loader, not the original file directly

---

The third and most important stage

```py
def build_stub(hex_body: str, digest: str, size: int) -> str:
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
```

In the **third stage**, the main stub stores the outer loader as hex and checks its hash
If everything is valid, it decodes the hex back to code and starts the outer loader
This is the main entry point that launches all other stages

---
The hidden **fourth stage** (final loader)

---

```py
execution_code = "exec(zlib.decompress(lzma.decompress(base64.b64decode((" + "+".join(all_vars) + ").replace('☭','')))))"
```

In the **final stage**, the compressed stub is **split into 10 variables** with **delimiter obfuscation** using `☭`. At runtime, these fragments are **reassembled, decoded from Base64, and decompressed** through **zlib and LZMA** layers, then executed — creating a stealthy, fragmented loader that evades static detection

**The final touches — and the ending is pure perfection**


---

# **Features**

* **Anti-Debug**
* **Anti-Tamper**
* **Hex-Encoded Loader**
* **Random Variable Renaming**
* **Double-Layer Compression**
* **Double-Layer AES-GCM Encryption**
* **Key Derivation Based on File Size**
* **Hex-Encoded Strings**
* **Runtime Integrity Verification**
* **Multi-Stage Decoding Pipeline**
* **Dynamic Module Checks**

---

### Old Script vs New Script 

| Aspect                 | Old Script (PyArmor Wrapper)                                           | New Script (Current)                                                                     |
| ---------------------- | ---------------------------------------------------------------------- | ---------------------------------------------------------------------------------------- |
| **Core idea**          | Just asks for a file name and runs `pyarmor-7 o <file>`                | Implements its own multi-stage encryption & loading pipeline                             |
| **Protection engine**  | Fully depends on PyArmor's built-in protection                         | Custom AES-GCM + zlib + file-size based key derivation + multi-stage loaders             |
| **Stub complexity**    | No stub, target file is passed directly to PyArmor                     | Three-stage stub (inner loader, outer loader, main stub) with layered execution          |
| **Anti-Debug**         | None                                                                   | Multiple anti-debug checks (`sys.gettrace`, known debug modules, etc.)                   |
| **Anti-Tamper**        | None                                                                   | Verifies SHA-256 digest of the hex-encoded loader before execution                       |
| **Encoding style**     | No extra encoding, PyArmor handles everything                          | Loaders and critical strings stored as hex / base64 and reconstructed at runtime         |
| **Layers of security** | Single tool call (PyArmor applies its own single pipeline)             | Double compression + double AES-GCM + hex-encoded outer stub                             |
| **Randomization**      | No random names                                                        | Random variable names generated per build for every important symbol                     |
| **Dependencies**       | Requires `pyarmor-7` binary to be installed and in PATH                | Pure Python implementation using `pycryptodome` (`Crypto.Cipher.AES`) and stdlib only    |
| **Output control**     | Limited control: PyArmor decides structure of the protected file       | You fully control the stub structure, loaders, constants, and how the file is executed   |
| **Detection surface**  | Signature/behavior mostly looks like a normal PyArmor-protected script | Custom layout, custom math for keys, custom stub → less "generic" / more unique per tool |

---

**By Freemasonry**
