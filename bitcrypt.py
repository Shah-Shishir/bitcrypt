#!/usr/bin/env python
# -*- coding: utf-8 -*-


'''
Simple AES256 encryption using Bitcoin public and private keys.

The mac uses a pbkdf2 function, because computing the mac needs to be
more resource intensive than decryption, so that an adversary cannot
brute force through macs in order to reduce the search space for
possible decryption keys.

Requires:  pbkdf2, PyCrypto, simplebitcoinfuncs
'''


from __future__ import print_function
try:
    from __builtin__ import raw_input as input
except ImportError:
    pass
import os
import sys
import hashlib
import hmac
import base64
import datetime
from getpass import getpass
from binascii import hexlify, unhexlify
from pbkdf2 import PBKDF2
from Crypto.Cipher import AES
from simplebitcoinfuncs.hexhashes import sha512d, hash256
from simplebitcoinfuncs.miscfuncs import strlify, hexstrlify, normalize_input
from simplebitcoinfuncs.miscbitcoinfuncs import genkeyhex, genkey
from simplebitcoinfuncs.bitcoin import uncompress, compress, privtopub, multiplypub, validatepubkey, privtohex


macrounds = 2000 # Do not chage unless the other party also changes!


def bitencrypt(recipient_pubkey,message,sender_privkey=genkeyhex()):
    '''
    Encrypt a message to a public key. The third argument can be your
    own private key if you want the recipient to know you are the
    sender. (Your public key, unencrypted, is part of the output,
    so the whole world will also know you are the sender.) For an
    anonymous message, just let the function make a new random key.

    EC multiplication using the input private key and the recipient
    public key is used to derive a shared secret which is used as
    the AES encryption key.
    '''

    recipient_pubkey = validatepubkey(recipient_pubkey)
    assert recipient_pubkey
    if recipient_pubkey[:2] == '04':
        recipient_pubkey = compress(recipient_pubkey)
    sender_privkey = privtohex(sender_privkey)
    sender_pubkey = privtopub(sender_privkey,True)
    try:
        message = message.encode('utf-8')
    except: pass
    numpads = 16 - (len(message) % 16)
    try:
        message = message + (numpads * chr(numpads))
    except:
        message = message + bytes(numpads * chr(numpads).encode("utf-8"))
    iv = hash256(hexlify(os.urandom(40) + \
                str(datetime.datetime.now()).encode("utf-8")))[:32]
    secret_key = multiplypub(recipient_pubkey,sender_privkey,True)
    encryption_key = hash256(secret_key)
    encryption_key, iv = unhexlify(encryption_key), unhexlify(iv)
    e = AES.new(encryption_key, AES.MODE_CBC, iv)
    cipher = e.encrypt(message)
    o = iv + cipher
    mac = PBKDF2(unhexlify(sha512d(secret_key)),o,macrounds, \
                 macmodule=hmac,digestmodule=hashlib.sha256).read(16)
    o = base64.b64encode(unhexlify(sender_pubkey) + o + mac)
    if 'bytes' == type(o).__name__ and str(o)[:2] == "b'":
        o = str(o)[2:-1]
    return o


def bitdecrypt(message,privkey):
    '''
    Decrypt a message encrypted with the previous function.

    Returns a tuple of (sender's pubkey, message) upon successful
    decryption, and (sender's pubkey, False) upon failure.

    Authentication is proved by successful decryption, as is proof
    that the public key attached to the message is indeed the sender.
    '''

    message = hexstrlify(base64.b64decode(message))
    privkey = privtohex(privkey)
    sender_key = message[:66]
    assert sender_key[:2] == '02' or sender_key[:2] == '03'
    mac = unhexlify(message[-32:])
    iv = unhexlify(message[66:98])
    message = unhexlify(message[98:-32])
    secret_key = multiplypub(sender_key,privkey,True)
    testmac = PBKDF2(unhexlify(sha512d(secret_key)),iv + message, \
                     macrounds,macmodule=hmac, \
                     digestmodule=hashlib.sha256).read(16)
    if testmac != mac:
        return sender_key, False
    encryption_key = unhexlify(hash256(secret_key))
    e = AES.new(encryption_key, AES.MODE_CBC, iv)
    message = e.decrypt(message)
    try:
        assert message
        assert not len(message) % 16
    except:
        return sender_key, False
    try:
        numpads = int(ord(message[-1]))
    except:
        numpads = int(message[-1])
    assert numpads < 17
    message = message[:-numpads]
    try:
        assert sys.version_info[0] == 2
        message = message.encode('ascii')
    except:
        try:
            if 'bytes' == type(message).__name__:
                message = str(message)[2:-1]
        except: pass
    return sender_key, message


if __name__ == "__main__":

    import argparse

    parser = argparse.ArgumentParser(description = \
              'Bitcrypt is simple command line app for doing AES256 ' + \
              'encryption and decryption using Bitcoin public and ' + \
              'private keys.', \
               epilog="Example:  cat mymessage.txt | bitcrypt -e -m - -p i -r 03fd4ebcbad1c9dde380b85b61051d7b219721fdd29673c83dad49577e98d959c4")

    parser.add_argument('--encrypt', '-e', action='store_true', \
                        help='Encrypt a message.')

    parser.add_argument('--decrypt', '-d', action='store_true', \
                        help='Decrypt a message.')

    parser.add_argument('--message', '-m', nargs=1, help='The text ' + \
        'to encrypt or decrypt. Use a single hyphen to get message ' + \
        'text from stdin. (Hyphen can be used either for private key ' + \
        'input or message input, but not both.)', default=[])

    parser.add_argument('--recipient', '-r', nargs='?', help='The ' + \
        'Bitcoin public key of the recipient. (Arg required when ' + \
        'encrypting.)', default=None)

    parser.add_argument('--priv', '-p', nargs='?', help='Your private ' + \
        'key. If encrypting, your public key will be in the message ' + \
        'in plaintext and identify you as the sender. For encryption, ' + \
        'this argument is optional, and if it is omitted, a new ' + \
        'random key will be used. (Use "-p i" or "--priv i" to ' + \
        'indicate you want to enter your private key manually.) For ' + \
        'decryption, this argument is required, and if it is omitted, ' + \
        'you will be asked to enter your private key. Use a single ' + \
        'hyphen to indicate that the key should be read from stdin. ' + \
        '(Hyphen can be used either for private key input or message ' + \
        'input, but not both.)', default='i')

    args = parser.parse_args()

    if args.encrypt:
        if args.decrypt:
            print('\nYou must use either the encrypt flag or the decrypt ' + \
                  'flag, but not both. Use the --help flag for more ' + \
                  'information.')
            exit(1)
        try:
            x = args.message[0]
        except:
            print("\nYou must enter a message to encrypt. Use the " + \
                  "--help flag for more information.")
            exit(1)
        if args.message[0] == '-':
            if args.priv == '-':
                print('\nEither the message input OR the private key ' + \
                      'input can be read from stdin, but not both. ' + \
                      'Use the --help flag for more information.')
                exit(1)
            message = sys.stdin.read()
        elif not args.message[0] or not len(args.message):
            print("\nYou must enter a message to encrypt. Use the --help " + \
                  "flag for more information.")
            exit(1)
        else:
            message = args.message[0]

        if args.priv is None:
            priv = genkey()
        elif args.priv == '-':
            priv = sys.stdin.read()
        elif args.priv == 'i':
            priv = getpass('\nEnter your private key: ')
        else:
            priv = args.priv
        priv = strlify(priv).replace('\r','').replace('\n','').replace(' ','')

        recipient = args.recipient
        while True:
            if not recipient or recipient is None:
                recipient = getpass("Please enter the recipient's public " + \
                                    "key: ")
                            # input() reads from stdin

            else:
                recipient = args.recipient
            recipient = strlify(recipient).replace('\r','').replace('\n','').replace(' ','')
            recipient = validatepubkey(recipient)
            try:
                assert recipient
            except:
                print("\nInvalid public key entered for recipient. " + \
                      "Remember, a public key is not an address. " + \
                      "It is hex that begins with 02, 03, or 04. " + \
                      "Use the --help flag for more information.\n")
            else:
                print()
                break

    else:
        if not args.decrypt:
            print('\nYou must use the --encrypt flag or the --decrypt ' + \
                  'flag. Use the --help flag for more information.')
            exit(1)
        try:
            x = args.message[0]
        except:
            print("\nYou must enter a message to encrypt. Use the " + \
                  "--help flag for more information.")
            exit(1)
        if not args.message[0] or not len(args.message):
            print("\nYou must enter a message to encrypt. Use the " + \
                  "--help flag for more information.")
            exit(1)
        elif args.message[0] == '-':
            if args.priv == '-':
                print('\nEither the message input OR the private key ' + \
                      'input can be read from stdin, but not both. ' + \
                      'Use the --help flag for more information.')
                exit(1)
            message = sys.stdin.read()
        else:
            message = args.message[0]
        message = strlify(message).replace('\r','').replace('\n','').replace(' ','')
        # message is base64 at this point

        if args.priv is None or args.priv == 'i':
            priv = getpass('\nEnter your private key for decryption: ')
        elif args.priv == '-':
            priv = sys.stdin.read()
        else:
            priv = args.priv
        priv = strlify(priv).replace('\r','').replace('\n','').replace(' ','')

    while True:
        try:
            priv = privtohex(priv)
        except:
            print("\nInvalid private key entered. Please re-enter " + \
                  "your private key.\n")
            priv = strlify(getpass('Private key: '))
            priv = priv.replace('\r','').replace('\n','').replace(' ','')
        else:
            break

    if args.encrypt:
        try:
            o = bitencrypt(recipient,message,priv)
        except:
            print('\nUnknown fatal error occured during encryption ' + \
                  'attempt. Exiting...')
            exit(1)
        else:
            print(normalize_input(o))
            exit(0)

    else:
        try:
            o1, o2 = bitdecrypt(message,priv)
        except Exception as e:
            print('\nUnknown fatal error occured during decryption ' + \
                  'attempt. Exiting...')
            exit(1)
        else:
            print("\nMessage From:\n" + o1 + "\n")
            if not o2:
                print('Decryption was not possible with your private ' + \
                      'key. Message was either corrupted or you were ' + \
                      'not the intended recipient.\n')
            else:
                print('Message Reads:')
                print(o2)
                print()
            exit(0)

