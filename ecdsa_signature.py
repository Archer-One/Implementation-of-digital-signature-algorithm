#!/usr/bin/env python
# _*_ coding: utf-8 _*_
"""
# @Time : 9/21/21 11:25 PM
# @Author : Archer
# @File : ecdsa_signature.py
# @desc :
"""
from ecdsa import SigningKey, SECP256k1, VerifyingKey

def genetor_keys():
    sk = SigningKey.generate(curve=SECP256k1)
    vk = sk.get_verifying_key()
    secret_key = sk.to_string().hex()
    verify_key = vk.to_string().hex()
    return secret_key,verify_key

def sign(secret_key, m):
    sk = SigningKey.from_string(bytes.fromhex(secret_key), curve=SECP256k1)
    signature = sk.sign(bytes(m, 'utf-8'))
    return signature.hex()


def verify(verify_key, signature, m):
    vk = VerifyingKey.from_string(bytes.fromhex(verify_key), curve=SECP256k1)
    return vk.verify(bytes.fromhex(signature), bytes(m, 'utf-8'))

if __name__ == '__main__':
    sk, pk = genetor_keys()
    m = 'hello'
    signature = sign(sk, m)

    print('signature: ', signature)
    print('verification result: ', verify(pk, signature))