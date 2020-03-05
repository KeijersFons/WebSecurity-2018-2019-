# -*- coding: utf-8 -*-

import os
import zipfile
from Crypto.Cipher import PKCS1_OAEP, AES
from Crypto.Hash import SHA256
from Crypto.PublicKey import RSA
from Crypto.Signature import PKCS1_v1_5
from PIL import Image


class Decrypt:
    def __init__(self):
        # var die later gebruikt wordt om te kijken of de signature authentic is
        self.is_authentic = False

    def verSignature(self, publickeyP, fileP):
        # gedecrypteerde file's hash maken

        hash = SHA256.new()
        hash.update(open(fileP, "r").read())

        # publickey inlezen en verifier inmaken om beide hashes te verifieren

        keyPair = RSA.importKey(open(publickeyP, "r").read())
        verifier = PKCS1_v1_5.new(keyPair.publickey())

        # als de verifier klopt, en beide hashes zijn correct, print dan of de hash authentic is of niet

        if verifier.verify(hash, open(fileP.split('.')[0] + ".sig", "r").read()):
            print("The signature is authentic.")
            self.is_authentic = True
            print("SHA-256 -> %s" % hash.hexdigest())
            return True
        else:
            print("The signature is not authentic.")
            return False

    def keyReader(self, privekeyP, fileP):
        # Reading private key to decipher symmetric key used

        keyPair = RSA.importKey(open(privekeyP, "r").read())
        keyDecipher = PKCS1_OAEP.new(keyPair)

        # Reading iv and symmetric key used during encryption

        f = open(fileP.split('.')[0] + ".key", "r")
        iv = f.read(16)

        #printen of key valid is of niet

        try:
            k = keyDecipher.decrypt(f.read())
        except TypeError:
            return 0, "Invalid key."
        except ValueError:
            return 0, "Invalid key."

        return k, iv

    def decipher(self, publickeyP, privekeyP, fileP):
        # gebruikte symetric key en iv krijgen die bij het encryptieproces gegenereerd zijn

        k, iv = self.keyReader(privekeyP, fileP)

        if k != 0:
            # als we een symetric key hebben decrypten we de message en saven we dit in een file zonder extentie

            keyDecipher = AES.new(k, AES.MODE_CFB, iv)
            bin = open(fileP + ".bin", "rb").read()
            print "Decipher output: " + str(fileP)
            f = open(fileP.split('.')[0], "wb")
            f.write(keyDecipher.decrypt(bin))
            f.close()

            # verifcating signature

            sig_verified = self.verSignature(publickeyP, fileP.split('.')[0])

            if sig_verified is False:
                return "sig_false"
            else:
                return "success"
        else:
            return iv

    def auxFilesUnzip(self, all):
        # inputfile openen en alles unzippen

        f = zipfile.ZipFile(all + ".all", "r")
        f.extractall()

    def cleanupUsedFiles(self, sig, key, bin, all):
        # alle overbodige files verwijderen op het einde

        os.remove(sig)
        os.remove(key)
        os.remove(bin)
        os.remove(all)

    def filesChecker(self, f_name, pubKey, priKey, first_run):
        # checker of alle files accesable of writeable zijn

        if first_run:

            if not os.path.isfile(f_name + ".all") or not os.access(f_name + ".all", os.R_OK):
                print("Invalid file to decrypt. Aborting...")
                return "Invalid file to decrypt."

            if not os.path.isfile(pubKey) or not os.access(pubKey, os.R_OK):
                print("Invalid public key file. Aborting...")
                return "Invalid public key file."

            if not os.path.isfile(priKey) or not os.access(priKey, os.R_OK):
                print("Invalid private key file. Aborting...")
                return "Invalid private key file."

        elif not first_run:

            if not os.path.isfile(f_name + ".sig") or not os.access(f_name + ".sig", os.R_OK):
                print("Invalid *.sig file. Aborting...")
                return "Invalid *.sig file."
            if not os.path.isfile(f_name + ".key") or not os.access(f_name + ".key", os.R_OK):
                print("Invalid *.key file. Aborting...")
                return "Invalid *.key file."
            if not os.path.isfile(f_name + ".bin") or not os.access(f_name + ".bin", os.R_OK):
                print("Invalid *.bin file. Aborting...")
                return "Invalid *.bin file."

            if os.path.isfile(f_name) and not os.access(f_name, os.W_OK):
                print("Can't create output file. Aborting...")
                return "Can't create output file."

        return 1

    def txt_decode(self, imp):
        imp = os.path.abspath(imp)
        Im = Image.open(imp)
        pixels = Im.load()
        size = (pixels[0, 0][0]) + (pixels[0, 0][1]) * 256 + (pixels[0, 0][2]) * 65536
        t = []

        for i in range(1, size + 1):
            t.append(chr((pixels[0, i][0] % 10) * 100 + (pixels[0, i][1] % 10) * 10 + (pixels[0, i][2] % 10)))

        te = "".join(t)
        return te
