# bitcrypt
A simple cli app for AES-256 encryption and decryption using Bitcoin public and private keys

Works in Python 2 and 3.

Requires: PyCrypto, pbkdf2, simplebitcoinfuncs


    -h, --help            show this help message and exit
    --encrypt, -e         Encrypt a message.
    --decrypt, -d         Decrypt a message.
    --message MESSAGE, -m MESSAGE
                          The text to encrypt or decrypt. Use a single hyphen to
                          get message text from stdin. (Hyphen can be used
                          either for private key input or message input, but not
                          both.)
    --recipient [RECIPIENT], -r [RECIPIENT]
                          The Bitcoin public key of the recipient. (Arg required
                          when encrypting.)
    --priv [PRIV], -p [PRIV]
                          Your private key. If encrypting, your public key will
                          be in the message in plaintext and identify you as the
                          sender. For encryption, this argument is optional, and
                          if it is omitted, a new random key will be used. (Use
                          "-p i" or "--priv i" to indicate you want to enter
                          your private key manually.) For decryption, this
                          argument is required, and if it is omitted, you will
                          be asked to enter your private key. Use a single
                          hyphen to indicate that the key should be read from
                          stdin. (Hyphen can be used either for private key
                          input or message input, but not both.)

###Examples:

    python bitcrypt.py -e -m 'hello' -p i -r 02316cef96f58ba765bd4088855b3b946f8b1b657bf724eafdf0a6144f4d3d1cfb

    cat hello.txt | python bitcrypt.py -e -m - -p L5k6WCAhEmuZb974oUyQRxhkvWGgG8ZrXBSer39ZwezYGfudwRNV -r 02316cef96f58ba765bd4088855b3b946f8b1b657bf724eafdf0a6144f4d3d1cfb

    echo 'L5k6WCAhEmuZb974oUyQRxhkvWGgG8ZrXBSer39ZwezYGfudwRNV' | python bitcrypt.py -e -m 'hello' -p - -r 02316cef96f58ba765bd4088855b3b946f8b1b657bf724eafdf0a6144f4d3d1cfb

    python bitcrypt.py -d -m 'Ag+46lI6K/KP6YvfeFj7nu7MEyr3vsMeguCK8eGq5YXMJ/ROXMhBFGheEMQumI4fJl1ZykBMrBTfBBJwQonx7Vg5lBlB9vUKJbxXr5P7BKWt' -p i

    python bitcrypt.py -d -m 'Ag+46lI6K/KP6YvfeFj7nu7MEyr3vsMeguCK8eGq5YXMJ/ROXMhBFGheEMQumI4fJl1ZykBMrBTfBBJwQonx7Vg5lBlB9vUKJbxXr5P7BKWt' -p L3mRUisE32PBxyUcqERRBQ7ZArPVM7ZjrQj16f9WQ8qa5nvWRKfk

