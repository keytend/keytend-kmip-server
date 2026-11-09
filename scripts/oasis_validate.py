#!/usr/bin/env python3
# Copyright 2026 Jeremiah Jordan
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

"""Independent checks for variable trace output (pyca/cryptography, never the server).

Each check returns a short description when the server's value is verified and
raises AssertionError when it is wrong. A missing input raises Unverifiable, so
the caller can leave the obligation open instead of granting a pass.
"""
import hashlib,hmac
from cryptography.hazmat.primitives import hashes,serialization,padding as sympad,cmac
from cryptography.hazmat.primitives.asymmetric import padding,rsa,ec,utils
from cryptography.hazmat.primitives.ciphers import Cipher,algorithms,modes
from cryptography.hazmat.primitives.ciphers.aead import AESGCM,ChaCha20Poly1305
from cryptography.exceptions import InvalidSignature,InvalidTag

class Unverifiable(Exception):pass

def strict_decode(raw):
    """Decode one TTLV item, rejecting malformed encodings the test decoder tolerates.

    KMIP 2.1 section 9.1: fixed-size items have fixed lengths, Text/Byte Strings
    are padded to a multiple of eight bytes, Booleans are 0 or 1, and a structure's
    length is exactly that of its contents. Padding must be zero bytes.
    """
    def item(b,at,path):
        if len(b)-at<8:raise AssertionError(path+': truncated item header')
        tag=int.from_bytes(b[at:at+3],'big');kind=b[at+3];size=int.from_bytes(b[at+4:at+8],'big')
        if tag>>16!=0x42 and tag>>16!=0x54:raise AssertionError(f'{path}: tag {tag:06x} outside KMIP and extension ranges')
        fixed={2:4,3:8,5:4,6:8,9:8,10:4,11:8}
        if kind in fixed and size!=fixed[kind]:raise AssertionError(f'{path}/{tag:06x}: type {kind} length {size}')
        padded=size+(-size)%8 if kind not in (1,3,6,9,11) else size
        if kind==4 and (size%8 or size==0):raise AssertionError(f'{path}/{tag:06x}: Big Integer length not a positive multiple of 8')
        if kind==1 and size%8:raise AssertionError(f'{path}/{tag:06x}: structure length not a multiple of 8')
        end=at+8+padded
        if end>len(b):raise AssertionError(f'{path}/{tag:06x}: item exceeds enclosing length')
        raw=b[at+8:at+8+size];pad=b[at+8+size:end]
        if any(pad):raise AssertionError(f'{path}/{tag:06x}: nonzero padding')
        if kind==1:
            value=[];i=0
            while i<size:
                child,i2=item(raw,i,path+f'/{tag:06x}');value.append(child);i=i2
            if i!=size:raise AssertionError(f'{path}/{tag:06x}: structure contents overrun')
        elif kind in (2,5,10):
            value=int.from_bytes(raw,'big',signed=kind==2)
            if kind in (2,5,10) and any(pad):raise AssertionError('nonzero padding')
        elif kind in (3,9,11):value=int.from_bytes(raw,'big',signed=True)
        elif kind==6:
            value=int.from_bytes(raw,'big')
            if value not in (0,1):raise AssertionError(f'{path}/{tag:06x}: Boolean value {value}')
        elif kind in (7,12,13,14):
            try:value=raw.decode('utf-8')
            except UnicodeDecodeError:raise AssertionError(f'{path}/{tag:06x}: invalid UTF-8 text')
        elif kind in (4,8):value=raw
        else:raise AssertionError(f'{path}/{tag:06x}: unknown item type {kind}')
        return (tag,kind,value),end
    n,end=item(raw,0,'')
    if end!=len(raw):raise AssertionError(f'{len(raw)-end} trailing bytes after message')
    return n

HASHES={'SHA1':hashes.SHA1,'SHA224':hashes.SHA224,'SHA256':hashes.SHA256,'SHA384':hashes.SHA384,'SHA512':hashes.SHA512,'SHA3256':hashes.SHA3_256,'SHA3384':hashes.SHA3_384,'SHA3512':hashes.SHA3_512,'MD5':hashes.MD5}
def hash_of(name):
    if name not in HASHES:raise Unverifiable('hash '+str(name))
    return HASHES[name]()

def load_private(material,fmt):
    try:
        if fmt in ('PKCS1','PKCS8',None):return serialization.load_der_private_key(material,None)
        if fmt=='ECPrivateKey':return serialization.load_der_private_key(material,None)
    except ValueError as e:raise AssertionError('private key material does not parse: '+str(e))
    raise Unverifiable('private key format '+str(fmt))
def load_public(material,fmt):
    try:
        if fmt=='X509':return serialization.load_der_public_key(material)
        if fmt=='PKCS1':return serialization.load_der_public_key(_spki_rsa(material))
        if fmt is None:return serialization.load_der_public_key(material)
    except ValueError as e:raise AssertionError('public key material does not parse: '+str(e))
    raise Unverifiable('public key format '+str(fmt))
def _spki_rsa(pkcs1):
    # Wrap an RSAPublicKey (PKCS#1) in SubjectPublicKeyInfo for the loader.
    def der(tag,body):
        n=len(body);l=bytes([n]) if n<128 else bytes([0x80|((n.bit_length()+7)//8)])+n.to_bytes((n.bit_length()+7)//8,'big')
        return bytes([tag])+l+body
    alg=der(0x30,bytes.fromhex('06092a864886f70d0101010500'))
    return der(0x30,alg+der(0x03,b'\0'+pkcs1))

def public_of(key):
    """Accept a private or public key object and return the public key."""
    return key.public_key() if hasattr(key,'public_key') else key

def key_size_check(material,fmt,object_type,length,algorithm=None):
    """Verify generated key material is well formed and of the requested size."""
    if object_type=='SymmetricKey':
        if fmt not in ('Raw','TransparentSymmetricKey',None):raise Unverifiable('symmetric format '+str(fmt))
        if length is None:raise Unverifiable('no Cryptographic Length')
        if algorithm in ('3DES','DES3'):
            # A three-key 3DES bundle is 24 bytes; 168 counts the effective key
            # bits without the 24 parity bits, 192 counts them.
            if len(material)!=24 or length not in (168,192):raise AssertionError(f'3DES key is {len(material)} bytes for length {length}')
            if any(bin(b).count('1')%2==0 for b in material):raise AssertionError('generated 3DES key bytes lack odd parity')
            k1,k2,k3=material[:8],material[8:16],material[16:]
            if k1==k2 or k2==k3 or k1==k3:raise AssertionError('3DES key parts are not distinct')
            return f'3DES three-key bundle, odd parity, distinct parts (length {length})'
        if len(material)*8!=length:raise AssertionError(f'generated key is {len(material)*8} bits, attribute says {length}')
        if len(set(material))==1:raise AssertionError('generated key bytes are constant')
        return f'{length}-bit symmetric key, non-constant'
    key=load_private(material,fmt) if object_type=='PrivateKey' else load_public(material,fmt)
    size=getattr(key,'key_size',None) or getattr(getattr(key,'curve',None),'key_size',None)
    if length is not None and size is not None and size!=length:raise AssertionError(f'generated key is {size} bits, attribute says {length}')
    return f'{object_type} parses as {type(key).__name__.lstrip("_")} ({size} bits)'

def pair_check(private_key,public_key):
    if public_of(private_key).public_bytes(serialization.Encoding.DER,serialization.PublicFormat.SubjectPublicKeyInfo)!=public_key.public_bytes(serialization.Encoding.DER,serialization.PublicFormat.SubjectPublicKeyInfo):
        raise AssertionError('public key does not correspond to the private key')
    return 'private and public keys correspond'

def digest_check(material,algorithm,value):
    h=hashlib.new({'SHA256':'sha256','SHA1':'sha1','SHA384':'sha384','SHA512':'sha512','SHA224':'sha224'}.get(algorithm,'x'))  if algorithm in ('SHA256','SHA1','SHA384','SHA512','SHA224') else None
    if h is None:raise Unverifiable('digest algorithm '+str(algorithm))
    h.update(material)
    if h.digest()!=value:raise AssertionError(f'Digest Value is not {algorithm} of the key material in the stated format')
    return f'Digest Value recomputed as {algorithm} of the key material'

def sym_cipher(algorithm,key,mode,iv):
    if algorithm=='AES':alg=algorithms.AES(key)
    elif algorithm in ('3DES','DES3'):
        from cryptography.hazmat.decrepit.ciphers.algorithms import TripleDES
        alg=TripleDES(key)
    else:raise Unverifiable('symmetric algorithm '+str(algorithm))
    if mode=='ECB':return Cipher(alg,modes.ECB())
    if iv is None:raise Unverifiable('no IV available for '+mode)
    if mode=='CBC':return Cipher(alg,modes.CBC(iv))
    if mode=='CTR':return Cipher(alg,modes.CTR(iv))
    if mode=='CFB':return Cipher(alg,modes.CFB(iv))
    if mode=='OFB':return Cipher(alg,modes.OFB(iv))
    raise Unverifiable('block cipher mode '+str(mode))

def sym_decrypt(algorithm,key,mode,pad,iv,ciphertext,tag=None,aad=b''):
    if mode=='GCM':
        if iv is None or tag is None:raise Unverifiable('GCM without IV or tag')
        # Truncated tags (Tag Length < 16) are verified at their stated length.
        d=Cipher(algorithms.AES(key),modes.GCM(iv,tag,min_tag_length=min(len(tag),16))).decryptor()
        if aad:d.authenticate_additional_data(aad)
        try:return d.update(ciphertext)+d.finalize()
        except InvalidTag:raise AssertionError('GCM tag does not verify under the key')
    if algorithm=='ChaCha20Poly1305':
        try:return ChaCha20Poly1305(key).decrypt(iv,ciphertext+tag,aad or None)
        except InvalidTag:raise AssertionError('ChaCha20-Poly1305 tag does not verify')
    d=sym_cipher(algorithm,key,mode,iv).decryptor();plain=d.update(ciphertext)+d.finalize()
    if pad=='PKCS5':
        u=sympad.PKCS7(64 if algorithm in ('3DES','DES3') else 128).unpadder()
        try:plain=u.update(plain)+u.finalize()
        except ValueError:raise AssertionError('PKCS#5 padding invalid after independent decryption')
    return plain

# KMIP 2.1 Cryptographic Parameters: an omitted Mask Generator Hashing
# Algorithm defaults to SHA-1, independently of the Hashing Algorithm.
def rsa_decrypt(private_key,data,pad,hash_name,mgf_hash,label=None):
    if pad=='OAEP':
        h=hash_of(hash_name or 'SHA1');m=hash_of(mgf_hash or 'SHA1')
        try:return private_key.decrypt(data,padding.OAEP(padding.MGF1(m),h,label or None))
        except ValueError:raise AssertionError('RSA-OAEP ciphertext does not decrypt under the corresponding private key')
    if pad in ('PKCS1v15',):
        try:return private_key.decrypt(data,padding.PKCS1v15())
        except ValueError:raise AssertionError('RSA PKCS#1 v1.5 ciphertext does not decrypt')
    raise Unverifiable('RSA padding '+str(pad))

def verify_signature(public_key,signature,data,pad,hash_name,mgf_hash=None,salt=None,prehashed=False,default_salts=None):
    h=hash_of(hash_name or 'SHA256')
    algo=utils.Prehashed(h) if prehashed else h
    try:
        if isinstance(public_key,rsa.RSAPublicKey):
            if pad=='PSS':
                p=padding.PSS(padding.MGF1(hash_of(mgf_hash or 'SHA1')),padding.PSS.AUTO if salt is None else salt)
                if salt is None and default_salts:
                    # An omitted Salt Length has a defined default; accept only the
                    # readings of that default, not any salt.
                    for candidate in default_salts:
                        try:public_key.verify(signature,data,padding.PSS(padding.MGF1(hash_of(mgf_hash or 'SHA1')),candidate),algo);break
                        except (InvalidSignature,ValueError):continue
                    else:raise AssertionError(f'PSS salt length is none of the default readings {default_salts}')
            elif pad in ('PKCS1v15',None):p=padding.PKCS1v15()
            else:raise Unverifiable('RSA signature padding '+str(pad))
            public_key.verify(signature,data,p,algo)
        elif isinstance(public_key,ec.EllipticCurvePublicKey):public_key.verify(signature,data,ec.ECDSA(algo))
        else:raise Unverifiable('signature key type '+type(public_key).__name__)
    except InvalidSignature:
        # Name the parameters that do verify, so a parameter-default question is
        # distinguishable from a wrong signature. The check itself still fails.
        found=[]
        if isinstance(public_key,rsa.RSAPublicKey):
            for m in ('SHA1','SHA256','SHA384','SHA512'):
                for p in ([padding.PSS(padding.MGF1(hash_of(m)),padding.PSS.AUTO)] if pad=='PSS' else [])+[padding.PKCS1v15()]:
                    for hn in ('SHA1','SHA256','SHA384','SHA512'):
                        try:public_key.verify(signature,data,p,hash_of(hn));found.append(f'{type(p).__name__} MGF1-{m} {hn}')
                        except (InvalidSignature,ValueError):pass
        raise AssertionError('signature does not verify under the public key with '+f'{pad} {hash_name} MGF1-{mgf_hash or "SHA1"}'+(f'; verifies with {sorted(set(found))}' if found else ''))
    return f'signature verified independently ({pad or "default"} {hash_name or "SHA256"})'

def unwrap(mode,key,wrapped,iv=None):
    from cryptography.hazmat.primitives import keywrap
    try:
        if mode=='NISTKeyWrap':return keywrap.aes_key_unwrap(key,wrapped)
        if mode=='AESKeyWrapPadding':return keywrap.aes_key_unwrap_with_padding(key,wrapped)
    except keywrap.InvalidUnwrap:raise AssertionError('wrapped key does not unwrap under the wrapping key')
    raise Unverifiable('wrapping mode '+str(mode))

def mac(algorithm,key,data):
    names={'HMACSHA1':'sha1','HMACSHA224':'sha224','HMACSHA256':'sha256','HMACSHA384':'sha384','HMACSHA512':'sha512'}
    if algorithm in names:return hmac.new(key,data,names[algorithm]).digest()
    if algorithm=='AES':
        c=cmac.CMAC(algorithms.AES(key));c.update(data);return c.finalize()
    raise Unverifiable('MAC algorithm '+str(algorithm))

# Re-deriving trace inputs under a server-generated key. The trace's literal
# ciphertext/signature was produced under the sample key; the expected server
# result (plaintext, Valid) is still compared exactly afterwards.
def sym_encrypt(algorithm,key,mode,pad,iv,plaintext,aad=b'',tag_length=16):
    if mode=='GCM':
        if iv is None:raise Unverifiable('GCM without IV')
        out=AESGCM(key).encrypt(iv,plaintext,aad or None);return out[:-16],out[-16:][:tag_length]
    if pad=='PKCS5':
        p=sympad.PKCS7(64 if algorithm in ('3DES','DES3') else 128).padder();plaintext=p.update(plaintext)+p.finalize()
    e=sym_cipher(algorithm,key,mode,iv).encryptor();return e.update(plaintext)+e.finalize(),None

def rsa_encrypt(public_key,data,pad,hash_name,mgf_hash,label=None):
    if pad=='OAEP':return public_key.encrypt(data,padding.OAEP(padding.MGF1(hash_of(mgf_hash or 'SHA1')),hash_of(hash_name or 'SHA1'),label))
    if pad=='PKCS1v15':return public_key.encrypt(data,padding.PKCS1v15())
    raise Unverifiable('RSA padding '+str(pad))

def sign(private_key,data,pad,hash_name,mgf_hash=None,salt=None,prehashed=False):
    h=hash_of(hash_name or 'SHA256');algo=utils.Prehashed(h) if prehashed else h
    if isinstance(private_key,rsa.RSAPrivateKey):
        if pad=='PSS':return private_key.sign(data,padding.PSS(padding.MGF1(hash_of(mgf_hash or 'SHA1')),padding.PSS.DIGEST_LENGTH if salt is None else salt),algo)
        return private_key.sign(data,padding.PKCS1v15(),algo)
    if isinstance(private_key,ec.EllipticCurvePrivateKey):return private_key.sign(data,ec.ECDSA(algo))
    raise Unverifiable('signing key type '+type(private_key).__name__)
