# -*- coding: utf-8 -*-

import os
import zipfile
from Crypto.Cipher import PKCS1_OAEP, AES
from Crypto.Hash import SHA256
from Crypto.PublicKey import RSA
from Crypto.Signature import PKCS1_v1_5
from Crypto import Random
from Crypto.Random import random
from PIL import Image


class Encrypt:

    def getSignature(self, privekeyP, fileP, passP):
        # bestand om te encrypteren in buffer zetten
        file = open(fileP, "r")
        buffer = file.read()
        file.close()

        # SHA256 hash maken van bestand
        hash = SHA256.new(buffer)

        # privekey inlezen om bestand mee te signen
        keyPair = RSA.importKey(open(privekeyP, "r").read(), passphrase=passP)
        signer = PKCS1_v1_5.new(keyPair)

        # bestand opslaan in .sig (signature) bestand, dit is file_3 in de opgave
        relative = fileP.split('/')[-1]
        f = open("files/" + relative.split('.')[0] + ".sig", "w+")
        f.write(signer.sign(hash))
        f.close()

    def keyGetter(self, publickeyP, fileP, iv):
        # Hash van 1024 random bits maken

        hash = SHA256.new(str(random.getrandbits(1024)))

        # public key inlezen om symetric key mee te encrypten

        keyPair = RSA.importKey(open(publickeyP, "r").read())
        keyCipher = PKCS1_OAEP.new(keyPair.publickey())

        # key encrypteren en naar file saven (file_2 in opgave
        relative = fileP.split('/')[-1]
        f = open("files/" + relative.split('.')[0] + ".key", "w+")
        f.write(iv + keyCipher.encrypt(hash.digest()))
        f.close()

        # gegenereerde key teruggeven om file mee te encrypteren

        return hash.digest()

    def encrypt(self, privekeyP, publickeyP, fileP):
        # file to encrypt openen in binary reading mode

        f = open(fileP, "rb")
        buffer = f.read()
        f.close()

        # signature maken en saven

        priPass = ""
        self.getSignature(privekeyP, fileP, priPass)

        # iv initialiseren voor AES

        iv = Random.new().read(AES.block_size)

        # symetric key genereren en saven

        k = self.keyGetter(publickeyP, fileP, iv)

        # message encrypteren en saven naar file (file_1 in opgave)

        keyCipher = AES.new(str(k), AES.MODE_CFB, iv)
        relative = fileP.split('/')[-1]
        f = open("files/" + relative.split('.')[0] + ".bin", "w+")
        f.write(keyCipher.encrypt(buffer))
        f.close()

    def auxFilesZip(self, sig, key, bin):
        # 1 file openen om alle file in te zetten

        f = zipfile.ZipFile(bin.split('.')[0] + ".all", "w")

        # elk argument naar file schrijven

        f.write(sig)
        f.write(key)
        f.write(bin)

        f.close()

    # STEGANOGRAPHY

    def txt_encode(self, imp, text):
        Im = Image.open(imp)

        pixel = Im.load()
        pixel[0, 0] = (len(text) % 256, (len(text) // 256) % 256, (len(text) // 65536))

        try:
            for i in range(1, len(text) + 1):
                k = list(pixel[0, i])
                k[0] = int(k[0] / 10) * 10 + ord(text[i - 1]) // 100
                k[1] = int(k[1] / 10) * 10 + ((ord(text[i - 1]) // 10) % 10)
                k[2] = int(k[2] / 10) * 10 + ord(text[i - 1]) % 10
                pixel[0, i] = tuple(k)
        except IndexError:
            return False

        f_out_filename = str(imp).split('.')[0] + 'Encoded.png'
        f_out_filename = 'files/' + str(f_out_filename).rsplit('/', 1)[1]
        Im.save(f_out_filename)
        return True
