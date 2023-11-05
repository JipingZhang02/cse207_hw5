# %%
from sage.all import *
import struct
import re
import base64
from Crypto.Cipher import AES
from Crypto import Random

# %%
PRINT_ON = False
TQDM_ON = PRINT_ON

def do_nothing(*args,**kwargs):
    pass
myprint = print if PRINT_ON else do_nothing

if TQDM_ON:
    from tqdm import tqdm
    def my_tqdm(iterable1,*args,**kwargs):
        return tqdm(iterable1,*args,**kwargs)
else:
    def my_tqdm(iterable1,*args,**kwargs):
        return iterable1

# %%
def floor_sqrt(num:int)->int:
    if not isinstance(num,int):
        raise ValueError(f"type of num is {type(num)}")
    if num<0:
        raise ValueError
    if num<2:
        return num
    l,r = 1,num>>1
    while l<r:
        m = (l+r+1)>>1
        if m*m>num:
            r=m-1
        else:
            l=m
    return l

# %%
key_header = '-----BEGIN PRETTY BAD PUBLIC KEY BLOCK-----\n'
key_footer = '-----END PRETTY BAD PUBLIC KEY BLOCK-----\n'

def b64_enc(s):
    return base64.encodebytes(s).decode("ascii")

def b64_dec(s):
    return base64.b64decode(s)

# Generate ElGamal public key (p,g,y=g^x mod p) in standardized PBP Diffie-Hellman group
def gen_public_key():
    p = 0x3cf2a66e5e175738c9ce521e68361676ff9c508e53b6f5ef1f396139cbd422d9f90970526fd8720467f17999a6456555dda84aa671376ddbe180902535266d383
    R = Integers(p)
    g = R(2)
    x = ZZ.random_element(2**128)
    y = g**x

    key = int_to_mpi(p)+int_to_mpi(g)+int_to_mpi(y)
    return key_header + b64_enc(key) + key_footer

# Our "MPI" format consists of 4-byte integer length l followed by l bytes of binary key
def int_to_mpi(z):
    s = int_to_binary(z)
    return struct.pack('<I',len(s))+s

# Get bytes representation of arbitrary-length long int
def int_to_binary(z):
    z = int(z)
    return z.to_bytes((z.bit_length() + 7) // 8, 'big')

# Read one MPI-formatted value beginning at s[index]
# Returns value and index + bytes read.
def parse_mpi(s,index):
    length = struct.unpack('<I',s[index:index+4])[0]
    xbytes = s[index+4:index+4+length]
    z = Integer(int.from_bytes(xbytes, 'big'))
    return z, index+4+length

# An ElGamal public key consists of a magic header and footer enclosing the MPI-encoded values for p, g, and y.
def parse_public_key(s):
    data = re.search(key_header+"(.*)"+key_footer,s,flags=re.DOTALL).group(1)
    data = b64_dec(data)
    index = 0
    p,index = parse_mpi(data,index)
    g,index = parse_mpi(data,index)
    y,index = parse_mpi(data,index)
    return {'p':p, 'g':g, 'y':y}

encrypt_header = '-----BEGIN PRETTY BAD ENCRYPTED MESSAGE-----\n'
encrypt_footer = '-----END PRETTY BAD ENCRYPTED MESSAGE-----\n'

# PKCS 7 pad message.
def pad(s,blocksize=AES.block_size):
    n = blocksize-(len(s)%blocksize)
    return s+bytes([n]*n)

# Encrypt string s using ElGamal encryption with AES in CBC mode.
# Generate a 128-bit symmetric key, encrypt it using ElGamal, and prepend the MPI-encoded ElGamal ciphertext to the AES-encrypted ciphertext of the message.
def encrypt(pubkey,s):
    p = pubkey['p']; R = Integers(p)
    g = R(pubkey['g']); y = R(pubkey['y'])
    k = ZZ.random_element(2**128)
    m = ZZ.random_element(2**128)

    output = int_to_mpi(g**k)+int_to_mpi(m*(y**k))

    aeskey = int_to_binary(m)
    iv = Random.new().read(AES.block_size)
    cipher = AES.new(aeskey, AES.MODE_CBC, iv)

    output += iv + cipher.encrypt(pad(s))

    return encrypt_header + base64.b64encode(output).decode("ascii") + encrypt_footer

# %%
def read_int(byte_arr:bytes):
    if not isinstance(byte_arr,bytes):
        raise ValueError
    b_arr_list = list(byte_arr)
    if len(b_arr_list)<4:
        raise ValueError
    big_int_byte_len = 0
    for i in range(4):
        big_int_byte_len += b_arr_list[i]<<(8*i)
    if len(b_arr_list)<4+big_int_byte_len:
        raise ValueError
    res = 0
    for byte_val in b_arr_list[4:4+big_int_byte_len]:
        res = (res<<8)+byte_val
    return res,bytes(b_arr_list[4+big_int_byte_len:])

def fast_pow_with_mod(a:int,b:int,moder:int)->int:
    res = 1
    while b>0:
        if b&1:
            res = (res*a)%moder
        a = (a*a)%moder
        b>>=1
    return res

def extended_gcd(a, b):
    if a == 0:
        return (b, 0, 1)
    else:
        g, y, x = extended_gcd(b % a, a)
        return (g, x - (b // a) * y, y)
    
def extended_euclidian(a,b):
    if not isinstance(a,int):
        raise ValueError
    if not isinstance(b,int):
        raise ValueError
    if a<=0 or b<=0:
        raise ValueError
    num1,num2 = a,b
    ka1,kb1,ka2,kb2=1,0,0,1
    while num2>0:
        floor_div_res = num1//num2
        num3 = num1%num2
        ka3,kb3=ka1-floor_div_res*ka2,kb1-floor_div_res*kb2
        num1,ka1,kb1 = num2,ka2,kb2
        num2,ka2,kb2 = num3,ka3,kb3
    return num1,ka1,kb1

def mod_inverse(a, m):
    g, x, y = extended_euclidian(a, m)
    if g != 1:
        raise ValueError(f"Modular inverse does not exist, a and m have gcd:{g}")
    else:
        return x % m
    
def mod_inverse_of_prime(a,m_p):
    a%=m_p
    if a%m_p==0:
        raise ValueError
    return fast_pow_with_mod(a,m_p-2,m_p)

def chinese_remainder_theorem(mode_infos):
    N = 1
    for (ni,resti) in mode_infos:
        N *= ni
    x = 0
    for i in range(len(mode_infos)):
        Ni = N // mode_infos[i][0]
        x += mode_infos[i][1] * Ni * mod_inverse(Ni, mode_infos[i][0])

    return x % N

# n = [3, 7, 5]  # Moduli
# a = [2, 3, 1]  # Remainders

# result = chinese_remainder_theorem(list(zip(n, a)))
# print(f"The solution is {result}")

def babystep_giantstep(prime_p:int,generator_g:int,target_t:int,subgroup_order_q:int=-1)->int:
    if subgroup_order_q==-1:
        subgroup_order_q = prime_p-1
    # myprint(f"q={subgroup_order_q}")
    sqrt_q = floor_sqrt(subgroup_order_q)
    giantstep_map = dict()
    gstep_mul_factor = fast_pow_with_mod(generator_g,sqrt_q,prime_p)
    curr_gstep_val = 1
    for gstep in range(sqrt_q+1):
        if curr_gstep_val in giantstep_map:
            break
        giantstep_map[curr_gstep_val] = gstep*sqrt_q
        curr_gstep_val = (curr_gstep_val*gstep_mul_factor)%prime_p
    babystep_val,babystep_cnt = target_t,0
    while True:
        if babystep_val in giantstep_map:
            break
        babystep_val = (babystep_val*generator_g)%prime_p
        babystep_cnt+=1
        # if babystep_cnt>=2*sqrt_q+2:
        #     raise ValueError(f"cant find x such that {generator_g} to x mod {prime_p} is {target_t}")
    res = giantstep_map[babystep_val]-babystep_cnt
    while res<0:
        res+=subgroup_order_q
    return res



# %%
with open("./key.pub") as pubkey_file_in:
    pubkey_data = pubkey_file_in.read()

# %%
pubkey = parse_public_key(pubkey_data)

# %%
p = pubkey['p']
R = Integers(p)
g = R(pubkey['g'])
y = R(pubkey['y'])

# %%
g = int(g)
y = int(y)

# %%
with open("./hw5.pdf.enc.asc") as fin:
    encrypted_data_str = fin.read()


assert encrypted_data_str.startswith(encrypt_header)
assert encrypted_data_str.endswith(encrypt_footer)
encrypted_data_bytes = base64.b64decode(encrypted_data_str[len(encrypt_header):-len(encrypt_footer)])

# %%
g_to_k_mod_p,tmp1 = read_int(encrypted_data_bytes)
m_mul_y_to_k_mod_p,tmp2 = read_int(tmp1)
iv = tmp2[:AES.block_size]
enc_result = tmp2[AES.block_size:]


# %%
assert (len(enc_result)//AES.block_size)*AES.block_size==len(enc_result)

# %%
# g^k mod p = g_to_k_mod_p
# we should get k
# m*(y^k) mod p = output[1]
# aes_key = m

def pohlig_hellman_once(generator:int,mod_target:int,p:int,p_m_1_facor:int,t_this_factor:int):
    generator = int(generator)
    mod_target = int(mod_target)
    p=int(p)
    p_m_1_facor = int(p_m_1_facor)
    t_this_factor = int(t_this_factor)
    p_m_1 = p-1
    xs = list()
    alpha = generator
    beta = mod_target
    betas = list()
    betas.append(beta)
    q = p_m_1_facor
    pm1_div_qt = p_m_1//q
    alpha_to_pm1_div_qt = fast_pow_with_mod(alpha,pm1_div_qt,p)
    beta_to_pm1_div_qt = fast_pow_with_mod(beta,pm1_div_qt,p)
    #myprint(f"alpha_0={alpha_to_pm1_div_qt},beta_0={beta_to_pm1_div_qt}")
    x0 = babystep_giantstep(p,alpha_to_pm1_div_qt,beta_to_pm1_div_qt,q)
    xs.append(x0)
    for i in range(1,t_this_factor):
        pm1_div_qt//=q
        beta_i = (betas[-1]*mod_inverse_of_prime(fast_pow_with_mod(alpha,xs[-1],p),p))%p
        alpha_to_pm1_div_qt = fast_pow_with_mod(alpha,pm1_div_qt,p)
        beta_to_pm1_div_qt = fast_pow_with_mod(beta_i,pm1_div_qt,p)
        #myprint(f"alpha_{i}={alpha_to_pm1_div_qt},beta_{i}={beta_to_pm1_div_qt}")
        x_i = babystep_giantstep(p,alpha_to_pm1_div_qt,beta_to_pm1_div_qt,q)
        xs.append(x_i)
    mod_res = 0
    for x_i in xs[::-1]:
        mod_res = mod_res*q+x_i
    return (q**t_this_factor,mod_res)

# %%
p_m_1_factor_res = (p-1).factor()
p_m_1_factor_info = list(dict(p_m_1_factor_res).items())

# %%
moder = 1
mod_infos = list()
for tup in p_m_1_factor_info:
    myprint(f"now calculate remider info of {tup}")
    p_h_res_tup = pohlig_hellman_once(g,g_to_k_mod_p,p,tup[0],min(tup[1],1))
    mod_infos.append(p_h_res_tup)
    myprint(mod_infos)
    mod_res = chinese_remainder_theorem(mod_infos)
    moder*=p_h_res_tup[0]
    myprint(f"k={mod_res}(mod {moder})")
    if moder>=1<<128:
        break

# %%
# from math import log2

# log2(mod_res)

# %%
k=mod_res
m = (m_mul_y_to_k_mod_p*mod_inverse_of_prime(fast_pow_with_mod(y,k,p),p))%p

# %%
aeskey = int_to_binary(m)
cipher = AES.new(aeskey, AES.MODE_CBC, iv)
origin_msg = cipher.decrypt(enc_result)

with open("./hw5.pdf","wb+") as fout:
    fout.write(origin_msg)


