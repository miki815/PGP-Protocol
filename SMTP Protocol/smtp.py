import random
from tkinter import  *
from tkinter import messagebox, simpledialog
from tkinter import filedialog
import tkinter as tk
import tkinter.scrolledtext as st
import rsa
import datetime
import re
import hashlib
import zlib
import secrets
from Crypto.Util import number
from Crypto.PublicKey import DSA
from Crypto.PublicKey import ElGamal
from Crypto.Signature import  DSS
from Crypto.Hash import SHA1
from Crypto import Random


from Crypto.Cipher import CAST
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad
import base64
from Crypto.Util.Padding import unpad #------------------------------------------------------------------------------------------------------

def calculate_sha1(message_bytes):
    print("Poruka: " + message_bytes)
    if not isinstance(message_bytes, bytes):
        message_bytes = message_bytes.encode('utf-8')
    sha1_hash = hashlib.sha1(message_bytes).hexdigest()
    print("Hash poruke: "+str(sha1_hash))
    return sha1_hash

def getKeyID(key, isRsa):
    try:
        if key == None:
            return 0
    except:
        pass
    moduo = None
    if isRsa == 1:
        moduo = key.n
    else:
        moduo = key.y
    moduo_bin = bin(moduo)[2:]
    keyID = moduo_bin[-64:]
    print(keyID)
    return keyID

class PrivateRingField:
    def __init__(self, name, email, publicKey, privateKey, password, isRsa):
        self.name = name
        self.email = email
        self.publicKey = publicKey
        self.privateKey = privateKey
        self.timestamp = datetime.datetime.now()
        self.password = password
        self.userID = name + email
        self.row=1
        self.isRsa = isRsa
        self.keyID = getKeyID(publicKey, isRsa)
        self.publicGamal = None
        self.privateGamal = None
    def print(self):
        return self.userID
class PublicRingField:
    def __init__(self, name, email, publicKey, privateKey, isRsa):
        self.name = name
        self.email = email
        self.publicKey = publicKey
        self.privateKey = privateKey
        self.timestamp = datetime.datetime.now()
        self.userID = name + email
        self.isRsa = isRsa
        self.keyID = getKeyID(publicKey, isRsa)
        self.row = 1
        self.publicGamal = None
        self.privateGamal = None
    def print(self):
       return self.userID
PublicKeyRing = {}
PrivateKeyRing = {}
nextKeyRow = 11
currentPrivateKey = None
currentPublicKey = None

def generateWindow():
    root2 = Tk()
    root2.geometry("1300x1000")

    # Podaci
    nameVar = StringVar()
    emailVar = StringVar()
    lozinkaVar = StringVar()
    lozinkePrivatnih = []
    algoritamId = StringVar()
    keySize = IntVar()
    algoritamId.set("rsa")
    keySize.set(1024)

    Label(root2, text="Unesite podatke", font=("Arial", 20)).grid(row=0, column=1)
    ime1 = Label(root2, text="Ime", font=("Arial", 13)).grid(row=1, column=0)
    email1 = Label(root2, text="Email", font=("Arial", 13)).grid(row=2, column=0)
    ime = Entry(root2, textvariable=nameVar, width=30)
    ime.grid(row=1, column=1)
    email = Entry(root2, textvariable=emailVar, width=30)
    email.grid(row=2, column=1)

    # Algoritmi
    def selected():
        print(algoritamId.get())

    Label(root2, text="|", fg='orange', font=("Arial", 20)).grid(row=0, column=2)
    Label(root2, text="Izaberite algoritam", font=("Arial", 20)).grid(row=0, column=3)
    Radiobutton(root2, text="RSA", variable=algoritamId, value="rsa", font=("Arial", 13)).grid(row=1, column=3)
    Radiobutton(root2, text="DSA i El Gamal", variable=algoritamId, value="dsa", font=("Arial", 13)).grid(row=2, column=3)

    # VelicinaKljuca
    Label(root2, text="|", fg='orange', font=("Arial", 20)).grid(row=0, column=4)
    Label(root2, text="Izaberite velicinu kljuca", font=("Arial", 20)).grid(row=0, column=5)
    Radiobutton(root2, text="1024", variable=keySize, value=1024, font=("Arial", 13)).grid(row=1, column=5)
    Radiobutton(root2, text="2048", variable=keySize, value=2048, font=("Arial", 13)).grid(row=2, column=5)



    # Lozinka
    Label(root2, text="|", fg='orange', font=("Arial", 20)).grid(row=0, column=6)
    lozinka1 = Label(root2, text="Lozinka", font=("Arial", 20)).grid(row=0, column=7)
    lozinka = Entry(root2, textvariable=lozinkaVar, width=30, show="*")
    lozinka.grid(row=1, column=7)
    # Poruka
    poruka = Label(root2, fg='red', text="", font=("Arial", 13))
    poruka.grid(row=6, column = 5)
    Label(root2, text="|", fg='orange', font=("Arial", 20)).grid(row=0, column=8)
    labelJavniKljucevi = Label(root2, text="Javni/ucitani kljucevi", font=("Arial", 15))
    labelJavniKljucevi.grid(row = 10, column = 1)
    labelPrivatniKljucevi = Label(root2, text="Lozinka privatnog", font=("Arial", 15))
    labelPrivatniKljucevi.grid(row = 10, column = 3)

    def obrisi(row):
        i = -1
        find=""
        for id in PrivateKeyRing:
            for item in PrivateKeyRing[id]:
                i += 1
                pub=item.publicKey
                if item.row == row:
                    find=id
                    element = root2.grid_slaves(row=row, column=1)
                    if element:
                        element[0].grid_forget()
                    element = root2.grid_slaves(row=row, column=3)
                    if element:
                        element[0].grid_forget()
                    element = root2.grid_slaves(row=row, column=5)
                    if element:
                        element[0].grid_forget()
                    element = root2.grid_slaves(row=row, column=6)
                    if element:
                        element[0].grid_forget()
                    element = root2.grid_slaves(row=row, column=7)
                    if element:
                        element[0].grid_forget()
                    element = root2.grid_slaves(row=row, column=8)
                    if element:
                        element[0].grid_forget()
                    del PrivateKeyRing[id]
                    a=-1
                    for item in PublicKeyRing[find]:
                        a+=1
                        if item.publicKey == pub:
                            element = root2.grid_slaves(row=item.row, column=1)
                            if element:
                                element[0].grid_forget()
                            del PublicKeyRing[find]
                            break
                    break

        return

    def dohvatiPrivatni(publicKey, keyPass):
       # messagebox.showinfo("Public key", publicKey)
        currentUserId = nameVar.get() + emailVar.get()
        for ringItem in PrivateKeyRing[currentUserId]:
            if ringItem.publicKey == publicKey:
                password=calculate_sha1(keyPass.get()) #------------------------------------------------------------------------------------
                if ringItem.password == password:
                    global currentPrivateKey
                    currentPrivateKey = ringItem
                    if ringItem.isRsa == 1:
                        messagebox.showinfo("Private key", ringItem.privateKey)
                    else:
                        messagebox.showinfo("Private key", ringItem.privateKey.x)
                else:
                    messagebox.showinfo("Password failed", "Lozinka za pristup netacna!")
        return


    def ucitajPem():
        ringItem = None
        keyType = simpledialog.askstring("Tip", "RSA-1\tDSA-0")
        isPublic = simpledialog.askstring("Privatni/javni", "Javni-1\tPrivatni-0")
        keyType= int(keyType)
        isPublic = int(isPublic)
        if (keyType not in [0,1]) and (isPublic not in [0,1]) or (keyType==None) or (isPublic== None):
            messagebox.showinfo("Info", "Pogresne vrednosti!")
            return
        global nextKeyRow
        file_path = filedialog.asksaveasfilename(defaultextension=".pem")
        with open(file_path, 'rb') as f:
            text_area = st.ScrolledText(root2, width=20, height=2, font=("Arial", 12))
            text_area.grid(column=1, row=nextKeyRow, pady=10, padx=10)

            if isPublic == 1:
                publicKey = None
                if keyType == 1:
                    publicKey = rsa.PublicKey.load_pkcs1( f.read())
                else:
                    publicKey = DSA.import_key(f.read())
                ringItem = PublicRingField(nameVar.get(), emailVar.get(), publicKey, None, keyType)
                if keyType == 0:
                    file_path2 = filedialog.asksaveasfilename(defaultextension=".pem")
                    with open(file_path2, 'rb') as f2:
                        content = f2.read().decode('ascii')
                      #  print(f"GAMAL JAVNI {content}")
                      #  print(f"GAMAL JAVNI {content[34:-32]} KRAJ")
                        p1, p2, p3, p4 = content[34:-32].split('\n')
                        print(f"p1 {p1} \n p2 {p2}\n p3 {p3}")
                        ringItem. publicGamal = (int(p1), int(p2), int(p3))
            else:
                privateKey = None
                if keyType == 1:
                    privateKey = rsa.PrivateKey.load_pkcs1(f.read())
                else:
                    privateKey = DSA.import_key(f.read())
                ringItem = PublicRingField(nameVar.get(), emailVar.get(), None, privateKey, keyType)
                if keyType == 0:
                    file_path2 = filedialog.asksaveasfilename(defaultextension=".pem")
                    with open(file_path2, 'rb') as f2:
                        content = f2.read().decode('ascii')
                        #  print(f"GAMAL JAVNI {content}")
                        #  print(f"GAMAL JAVNI {content[34:-32]} KRAJ")
                        try:
                            p1, p2, p3, p4 = content.split('\n')
                            print(f"p1 {p1} \n p2 {p2}\n p3 {p3} \n p4 {p4}")
                            if p1 != '-----BEGIN ELGAMAL PRIVATE KEY-----':
                                messagebox.showerror('Greska', 'Fajl nije u dobrom formatu!')
                            else:
                                ringItem.privateGamal = (int(p2), int(p3))
                        except:
                            messagebox.showerror('Greska', 'Fajl nije u dobrom formatu!')
            ringItem.row = nextKeyRow
            if ringItem.userID not in PublicKeyRing:
                PublicKeyRing[ringItem.userID] = [ringItem]
            else:
                PublicKeyRing[ringItem.userID].append(ringItem)
            nextKeyRow += 1
            if isPublic == 1:
                if ringItem.isRsa == 0:
                    text_area.insert(tk.INSERT, f"DSA PUBLIC\n{ringItem.publicKey.y}\nELGAMAL PUBLIC{ringItem.publicGamal}")
                else:
                    text_area.insert(tk.INSERT, ringItem.publicKey)
            else:
                if ringItem.isRsa == 0:
                    text_area.insert(tk.INSERT, f"DSA PRIVATE\n{ringItem.privateKey.x}\nELGAMAL PRIVATE{ringItem.privateGamal}")
                else:
                    text_area.insert(tk.INSERT, ringItem.privateKey)
            text_area.configure(state='disabled')


    def potvrdi():
       # r.set(2)
        global nextKeyRow
      #  keySize.set(2048)
        if not re.match(r"[^@]+@[^@]+\.[^@]+", email.get()):
            poruka.config(text="Email nije u dobrom formatu.")
     #   elif not re.match(r"^(?=.*[a-z])(?=.*[A-Z])(?=.*\d)[a-zA-Z\d]{7,}$", lozinka.get()):
    #      poruka.config(text="Lozinka nije u dobrom formatu.")
        elif keySize.get() == 0:
            poruka.config(text="Niste uneli velicinu kljuca.")
        elif algoritamId.get() == 0:
            poruka.config(text="Niste uneli alogritam.")
        elif ime.get() == "":
            poruka.config(text="Niste uneli ime.")
        else:
            ringItem = None
            if  algoritamId.get() == "rsa":
                messagebox.showinfo("Info", "Izabrali ste RSA algoritam!")
                e,d=generateKeysRSA(keySize.get())
                #e, d = loadKeysRSA()

                ringItem = PrivateRingField(nameVar.get(), emailVar.get(), e, d, calculate_sha1(lozinkaVar.get()), 1)
             #   ringItem.keyID = getKeyID(e)
                # test
              #  mojaPoruka = "rsa encryption test"
              #  cipherPoruka = encrypt(mojaPoruka, e)
              #  messagebox.showinfo("cipher", cipherPoruka)
              #  desifrovanaPoruka = decrypt(cipherPoruka, d)
              #  messagebox.showinfo("M", desifrovanaPoruka)
            elif algoritamId.get() == "dsa":
                messagebox.showinfo("Info", "Izabrali ste DSA algoritam!")
                x, y, p, g, private_key_dsa, public_key_dsa = generateKeysElgamal(keySize.get())
                ringItem = PrivateRingField(nameVar.get(), emailVar.get(), public_key_dsa, private_key_dsa, calculate_sha1(lozinkaVar.get()), 0)
                ringItem.publicGamal = (g, p, y)
                ringItem.privateGamal = (p, x)
              #  ringItem.keyID = public_key_dsa.y
            ringItem.row=nextKeyRow
            if ringItem.userID not in PrivateKeyRing:
                PrivateKeyRing[ringItem.userID] = [ringItem]
            else:
                PrivateKeyRing[ringItem.userID].append(ringItem)
            privatnaLozinka = StringVar()
            lozinkePrivatnih.append(privatnaLozinka)
            lozinkeDuzina = len(lozinkePrivatnih)-1
            text_area = st.ScrolledText(root2, width = 20, height = 2, font=("Arial", 12))
            text_area.grid(column = 1, row = nextKeyRow, pady = 10, padx = 10)
            Entry(root2, textvariable = lozinkePrivatnih[lozinkeDuzina], width = 20).grid(column = 3, row = nextKeyRow)
            Button(root2, text="Privatni", bg='#c60', font=("Arial", 13), command=lambda: dohvatiPrivatni(ringItem.publicKey,lozinkePrivatnih[lozinkeDuzina])).grid(row=nextKeyRow, column=5)
            Button(root2, text=f"Obrisi kljuc {nextKeyRow - 10}", font=("Arial", 13),
                   command=lambda num=nextKeyRow: obrisi(num)).grid(row=nextKeyRow, column=6)
            Button(root2, text="PEM javni", font=("Arial", 13), command=lambda: pemJavni(ringItem.publicKey, ringItem.isRsa, ringItem.publicGamal)).grid(row=nextKeyRow, column=7)
            Button(root2, text="PEM privatni", font=("Arial", 13), command=lambda: pemPrivatni(ringItem.publicKey, ringItem.isRsa, lozinkePrivatnih[lozinkeDuzina])).grid(row=nextKeyRow, column=8)

            nextKeyRow += 1
            if ringItem.isRsa == 0:
                text_area.insert(tk.INSERT, f"DSA PUBLIC\n{ringItem.publicKey.y}\nElGamal PUBLIC\n{ringItem.publicGamal[2]}")
            else:
                text_area.insert(tk.INSERT,ringItem.publicKey)
            text_area.configure(state='disabled')


    Button(root2, text="Ucitaj kljuc", bg='#bdcc5c', font=("Arial", 13), command=lambda: ucitajPem()).grid(row=10, column=8)
    potvrdi = Button(root2, text="Potvrdi", bg='#6f6', font=("Arial", 13), command=potvrdi).grid(row=10, column=7)
    Button(root2, text="Posalji poruku", bg="#00FFD5" ,font=("Arial", 13),
           command=lambda: sendMessage(nameVar.get(), emailVar.get())).grid(row=10, column=5)
    Button(root2, text="Primi poruku",bg="#078CFF", font=("Arial", 13), command=lambda: receiveMessage()).grid(row=10,column=6)

    def pemJavni(publicKey, isRsa, publicGamal):
        file_path = filedialog.asksaveasfilename(defaultextension=".pem")
        with open(file_path, 'wb') as f:
            if isRsa == 1:
                f.write(publicKey.save_pkcs1('PEM'))
                messagebox.showinfo("PEM", "Sacuvan rsa javni kljuc.")
            else:
                f.write(publicKey.export_key())
                messagebox.showinfo("PEM", "Sacuvan dsa javni kljuc.")
        if isRsa == 0:
            file_path = filedialog.asksaveasfilename(defaultextension=".pem")
            with open(file_path, 'wb') as fg:
                fg.write('-----BEGIN ELGAMAL PUBLIC KEY-----'.encode())
                fg.write(str(publicGamal[0]).encode())
                fg.write('\n'.encode())
                fg.write(str(publicGamal[1]).encode())
                fg.write('\n'.encode())
                fg.write(str(publicGamal[2]).encode())
                fg.write('\n'.encode())
                fg.write('-----END ELGAMAL PUBLIC KEY-----'.encode())
                messagebox.showinfo("PEM", "Sacuvan elgamal javni kljuc.")


    def pemPrivatni(publicKey, isRsa, keyPass):
        file_path = filedialog.asksaveasfilename(defaultextension=".pem")
        currentUserId = nameVar.get() + emailVar.get()
        for ringItem in PrivateKeyRing[currentUserId]:
            if ringItem.publicKey == publicKey:
                password = calculate_sha1(keyPass.get())  # ------------------------------------------------------------------------------------
                if ringItem.password == password:
                    with open(file_path, 'wb') as f:
                        if isRsa == 1:
                            f.write((ringItem.privateKey).save_pkcs1('PEM'))
                            messagebox.showinfo("PEM", "Sacuvan rsa privatni kljuc.")
                        else:
                            f.write((ringItem.privateKey).export_key())
                            messagebox.showinfo("PEM", "Sacuvan dsa privatni kljuc.")
                            file_path = filedialog.asksaveasfilename(defaultextension=".pem")
                            with open(file_path, 'wb') as fg:
                                fg.write('-----BEGIN ELGAMAL PRIVATE KEY-----'.encode())
                                fg.write('\n'.encode())
                                fg.write(str(ringItem.privateGamal[0]).encode())
                                fg.write('\n'.encode())
                                fg.write(str(ringItem.privateGamal[1]).encode())
                                fg.write('\n'.encode())
                                fg.write('-----END ELGAMAL PRIVATE KEY-----'.encode())
                                messagebox.showinfo("PEM", "Sacuvan elgamal privatni kljuc.")
                else:
                    messagebox.showinfo("Greska", "Netacna lozinka za privatni kljuc.")
                return

    def rsaExport(key):
        with open('userA/publicKeys.pem', 'wb') as f:
            f.write(publicKey.save_pkcs1('PEM'))

    def rsaImport(fileName):
        with open('userA/publicKeys.pem', 'rb') as f:
            publicKey = rsa.PublicKey.load_pkcs1(f.read())

    def dsaExport(key):
        with open('userA/publicKeys.pem', 'wb') as f:
            f.write(public_key.export_key().decode())

    def dsaImport(fileName):
        with open('userA/publicKeys.pem', 'rb') as f:
            publicKey = DSA.import_key(f.read())



    def generateKeysRSA(size):
        (publicKey, privateKey) = rsa.newkeys(size)
        return publicKey, privateKey
    #    with open('userA/publicKeys.pem', 'wb') as f:
    #        f.write(publicKey.save_pkcs1('PEM'))
    #    with open('userA/privateKeys.pem', 'wb') as f:
    #        f.write(privateKey.save_pkcs1('PEM'))

    def generateKeysElgamal(size):
        private_key_dsa = DSA.generate(1024)
        public_key_dsa = private_key_dsa.publickey()
        p = number.getPrime(size)
        g = None
        found_g = False
        while not found_g:
            found_g = True
            g = number.getRandomRange(3, p)
            print(g)

        # private key
        x = number.getRandomRange(2, p - 1)
        # public key
        y = pow(g, x, p)
        return x, y, p, g, private_key_dsa, public_key_dsa

    def encryptElgamal(g, p, m, y):
        print(g)
        print(m)
        print(p)
        print(y)
      #  r = number.getRandomRange(2, p - 1)
        r = random.randint(1, p-2)
        c1 = pow(g, r, p)
        c2 = (int.from_bytes(m, "big") * pow(y, r, p)) % p
        return c1, c2

    def decryptElgamal(c1, c2, x, p):
        m = (c2 * pow(c1, p - 1 - x, p)) % p
        return m

    def signDSA(msg, private_key):
        hash_message = calculate_sha1(msg)
        signer = DSS.new(private_key, 'fips-186-3')
        signature = signer.sign(SHA1.new(msg.encode()))
        return signature

    def verifyDSA(msg, public_key, signature):
        verifier = DSS.new(public_key, 'fips-186-3')
        try:
            verifier.verify(SHA1.new(msg), signature)
            print("Potpis je validan.")
            return 1
        except ValueError:
            print("Potpis nije validan.")
        return 0

    def testElGamal_Dsa():
        # elGamalTesting
        x, y, p, g, private_key_dsa, public_key_dsa = generateKeysElgamal(2048)
        message = 42
        c1, c2 = encryptElgamal(g, p, message, y)
        decrypted_message = decryptElgamal(c1, c2, x, p)
        print("Originalna poruka ElGamal:", message)
        print("Dekriptovana poruka ElGamal:", decrypted_message)
        # dsa testing
        message = b"Hello, World!"
        signature = signDSA(message, private_key_dsa)
        verifyDSA(message, public_key_dsa, signature)


    def loadKeysRSA():
        with open('userA/publicKeys.pem', 'rb') as f:
            publicKey = rsa.PublicKey.load_pkcs1(f.read())
            f.close()
        with open('userA/privateKeys.pem', 'rb') as f:
            privateKey = rsa.PrivateKey.load_pkcs1(f.read())
            f.close()
        return publicKey, privateKey

    def encrypt(message, key):
        if not isinstance(message, bytes):
            message = message.encode('utf-8')
        return rsa.encrypt(message, key)

    def decrypt(ciphertext, key):
        try:
            return rsa.decrypt(ciphertext, key).decode('ascii')
        except Exception as e:
            print(e)
            return False

    def sign(message, key):
        return rsa.sign(message.encode('ascii'), key, 'SHA-1')

    def verify(message, signature, key):
        try:
            return rsa.verify(message.encode('ascii'), signature, key) == 'SHA-1'
        except:
            return False



    #DSA and ElGamal    ------------------------------------------------------------------------------------------------------------------






    def generateKeysElGamal(size):
        keypair = ElGamal.generate(1024, Random.new().read)
        publicKey=keypair.publickey()
        print(keypair.has_private())
        """with open('userA/publicKeysDSA.pem', 'wb') as f:
            f.write(publicKey.export_key('PEM'))
            f.close()
        with open('userA/privateKeysElGamal.pem', 'wb') as f:
            f.write(keypair.export_key('PEM', True, 'Key'))
            f.close()"""

        # Cast5    ------------------------------------------------------------------------------------------------------------------

    def cast5Encrypt(key, message):
        if not isinstance(message, bytes):
            message = message.encode('ascii')
        cipher = CAST.new(key, CAST.MODE_OPENPGP)
        msg = cipher.encrypt(message)
        return msg

    def cast5Decrypt(key, msg):
        eiv = msg[:CAST.block_size + 2]
        ciphertext = msg[CAST.block_size + 2:]
        cipher = CAST.new(key, CAST.MODE_OPENPGP, eiv)
        c = cipher.decrypt(ciphertext)
        return c
    #AES ------------------------------------------------------------------------------------------------------------------

    #https://pycryptodome.readthedocs.io/en/latest/src/cipher/aes.html

    def aes128Decrypt(key, encrypted_message):
        cipher = AES.new(key, AES.MODE_ECB)
        decrypted_message = cipher.decrypt(encrypted_message)
        unpadded_message = unpad(decrypted_message, AES.block_size)
        #decrypted_message_str = unpadded_message.decode('utf-8')
        return unpadded_message


    def aes128Encrypt(key, message):
        cipher = AES.new(key, AES.MODE_ECB)
        padded_message = pad(message, AES.block_size)
        ciphertext = cipher.encrypt(padded_message)
        return ciphertext

    #SEND MESSAGE -------------------------------------------------------------------------------------------------------------

    def convertToRadix(message, flag):
        if not isinstance(message, bytes):
            message = message.encode('ascii')
        base64_bytes = base64.b64encode(message)
        base64_message = base64_bytes.decode('utf-8')
        return base64_message

    def decode_base64_message(base64_message):
        decoded_bytes = base64.b64decode(base64_message)
        #decoded_message = decoded_bytes.decode('utf-8')
        return decoded_bytes

    def compress_message(message):
        message_bytes = message.encode('ascii')
        compressed_data = zlib.compress(message_bytes)
        compressed_bytes = bytes(compressed_data)
        return compressed_bytes

    def decompress_message(compressed_data):
        if not isinstance(compressed_data, bytes):
            compressed_data=compressed_data.decode('ascii')
        decompressed_data = zlib.decompress(compressed_data)
        decompressed_message = decompressed_data.decode('utf-8')
        return decompressed_message

    def setEncryptKey(ringItem):
        global currentPublicKey
        currentPublicKey = ringItem
        print(currentPublicKey.publicKey)
        messagebox.showinfo("Info", "Kljuc odabran.")


    def send(signOption, encryptOption, zipOption, radixOption, algoOption, msg):
        print(msg)
        cipherKey = None
        msgCipherHash = None
        isRsaPrivate = None
        if signOption == 0:
            msgHash = calculate_sha1(msg)
            global currentPrivateKey
            print(f"PRIVATE{currentPrivateKey.privateKey}")
            if currentPrivateKey.isRsa:
                msgCipherHash = encrypt(msgHash, currentPrivateKey.privateKey)
            else:
                msgCipherHash = signDSA(msg, currentPrivateKey.privateKey)
            isRsaPrivate = currentPrivateKey.isRsa
            messagebox.showinfo("cipher hash", msgCipherHash)
            msg = msg + str(msgCipherHash)
            print("Signed: " + msg)
        if zipOption == 0:
            msg = compress_message(msg)
            print("Compressed: " + str(msg))
        else: #--------------------------------------------------------------------------------------------------
            msg = msg.encode('ascii')
        if encryptOption == 0:
            key = secrets.token_bytes(16)
            if algoOption==0:
                msg = aes128Encrypt(key, msg)
            else:
                msg = cast5Encrypt(key, msg)
            print("Encrypted: " + str(msg))

            global currentPublicKey
         #   print(f"PUBLIC{currentPublicKey.publicKey}")
            print("CIPHER KEY: " + str(key))
            if currentPublicKey.isRsa == 1:
                cipherKey = encrypt(str(key), currentPublicKey.publicKey)
            else:
                cipherKey = encryptElgamal(currentPublicKey.publicGamal[0], currentPublicKey.publicGamal[1], key, currentPublicKey.publicGamal[2])
                print(f"Gamal encrypted key{cipherKey}")
        if radixOption == 0:
            if zipOption == 0:
                msg = convertToRadix(msg, 0)
            else:
                msg = convertToRadix(msg, 1)
            print("Radix64 format: " + str(msg))
        try:
            rsaPublicKeyID = str(getKeyID(currentPublicKey.publicKey, currentPublicKey.isRsa))
        except Exception:
            rsaPublicKeyID = -1
        try:
            rsaSignKeyId = str(getKeyID(currentPrivateKey.privateKey, currentPrivateKey.isRsa))
        except Exception:
            rsaSignKeyId = -1
        keyFlag = -1
        if rsaPublicKeyID != -1:
            keyFlag = currentPublicKey.isRsa
        elif rsaSignKeyId != -1:
            keyFlag =  currentPrivateKey.isRsa
        flags = str(signOption) + str(zipOption) + str(encryptOption) + str(radixOption) + str(algoOption) + str(keyFlag)

        rsaSignKeyId = str(getKeyID(currentPrivateKey.privateKey, currentPrivateKey.isRsa))
        fileName = filedialog.asksaveasfilename(defaultextension=".txt")
        with open(fileName, "w") as f:
            f.write(f"{flags}\n")
            if signOption == 0: #--------------------------------------------------------------------------------------------------------
                f.write(f"{rsaSignKeyId}\n")
            else:
                f.write("\n")
            if encryptOption == 0: #--------------------------------------------------------------------------------------------------------
                f.write(f"{rsaPublicKeyID}\n{cipherKey}\n")
            else:
                f.write("\n")
                f.write("\n")

            f.write(f"{str(msg)}\n")
            messagebox.showinfo("Poslata", "Poruka je poslata.")

    def sendMessage(nameVar, emailVar):
        root3 = Toplevel()
        root3.geometry("1200x500")
        trenutnaLozinka = StringVar()
        Label(root3, text="Poruka", font=("Arial", 15)).grid(row=0, column=0)
        Label(root3, text="Izaberi javni kljuc za tajnost", font=("Arial", 15)).grid(row=0, column=2)
        Label(root2, text="|", fg='orange', font=("Arial", 15)).grid(row=0, column=3)

        Label(root3, text="Lozinka privatnog kljuca za potpisivanje", font=("Arial", 15)).grid(row=0, column=4)

        Label(root3, text="Opcije za slanje", font=("Arial", 15)).grid(row=3, column=0)
        algoritamId1 = IntVar()
        signOption = IntVar()
        encryptOption = IntVar()
        zipOption = IntVar()
        radixOption = IntVar()
        #Label(root3, text="Opcije prilikom slanja", font=("Arial", 15)).grid(row=0, column=7)
        Checkbutton(root3, variable=signOption, text="Potpis", onvalue=0, offvalue=1, font=("Arial", 13)).grid(row=4, column=0)
        Checkbutton(root3, variable=encryptOption, text="Enkripcija", onvalue=0, offvalue=1, font=("Arial", 13)).grid(row=5, column=0)
        Checkbutton(root3, variable=zipOption, text="Kompresija", onvalue=0, offvalue=1, font=("Arial", 13)).grid(row=6, column=0)
        Checkbutton(root3, variable=radixOption, text="Radix-64 konverzija", onvalue=0, offvalue=1, font=("Arial", 13)).grid(row=7, column=0)
        messageText = Text(root3, height=5, width=52)
        messageText.grid(row=1, column=0)
        global  currentUserId
        currentUserId = nameVar + emailVar
        publicKey = StringVar()
        nextKeyRow = 1
        lozinkeDuzina = len(lozinkePrivatnih) - 1
        Label(root3, text="Izaberite algoritam", font=("Arial", 15)).grid(row=8, column=0,  padx=10, pady=10)
        Radiobutton(root3,  text="AES128" ,variable=algoritamId1, value=0, font=("Arial", 13)).grid(row=9, column=0)
        Radiobutton(root3,  text="CAST5" ,variable=algoritamId1, value=1, font=("Arial", 13)).grid(row=10, column=0)
        potvrdi = Button(root3, text="Potvrdi", bg='#6f6', font=("Arial", 13), command=lambda: send(signOption.get(), encryptOption.get(), zipOption.get(), radixOption.get(), algoritamId1.get(), messageText.get("1.0",END))).grid(row=11, column=0)


        #PrivateKeyRing-------------------------------------------------------------------------------------------------------------------
        for ringItem in PrivateKeyRing[currentUserId]:
            text_area = st.ScrolledText(root3, width=10, height=1, font=("Arial", 12))
            text_area.grid(column=2, row=nextKeyRow, pady=10, padx=10) #neca
            #Button(root3, text="Izaberi javni", bg='#6f6', font=("Arial", 13),  command=lambda ring=ringItem: setEncryptKey(ring)).grid(row=nextKeyRow, column=3)

            text_area.insert(tk.INSERT, "Javni kljuc")
            #if ringItem.isRsa == 0:
               # text_area.insert(tk.INSERT, f"DSA PUBLIC\n{ringItem.publicKey.y}\nElGamal PUBLIC\n{ringItem.publicGamal[2]}")
            #else:
                #text_area.insert(tk.INSERT,ringItem.publicKey)
            #text_area.configure(state='disabled')

            Entry(root3, textvariable=trenutnaLozinka, width=20).grid(column=4, row=nextKeyRow)
            Button(root3, text="Izaberi privatni", bg='#6f6', font=("Arial", 13),  command=lambda ring=ringItem: dohvatiPrivatni(ring.publicKey,trenutnaLozinka)).grid(row=nextKeyRow, column=5)

            nextKeyRow += 1

        index=-1
        for ringItem in PublicKeyRing:
            index+=1
            text_area = st.ScrolledText(root3, width=20, height=2, font=("Arial", 12))
            text_area.grid(column=2, row=nextKeyRow, pady=10, padx=10)  # neca
            try:
                Button(root3, text="Izaberi javni", bg='#6f6', font=("Arial", 13),
                       command=lambda ring=PublicKeyRing[ringItem][index]: setEncryptKey(ring)).grid(row=nextKeyRow, column=3)

                # text_area.insert(tk.INSERT, ringItem.publicKey)
                if PublicKeyRing[ringItem][index].isRsa == 0:
                    text_area.insert(tk.INSERT,
                                     f"DSA PUBLIC\n{PublicKeyRing[ringItem][index].publicKey.y}\nElGamal PUBLIC\n{PublicKeyRing[ringItem][index].publicGamal[2]}")
                else:
                    text_area.insert(tk.INSERT, PublicKeyRing[ringItem][index].publicKey)
                text_area.configure(state='disabled')
            except Exception:
                    a=1


            nextKeyRow += 1



        root3.mainloop()

    #RECEIVE MESSAG----------------------------------------------------------------------------------------------------------------------

    def readFile(fileName):
        text=None
        with open(fileName, 'rb') as f:
            text = f.read()
            f.close()
        return text

    def saveMessage(message, fileName):
        with open(fileName, 'w') as f:
            f.write(message)


    def receiveMessage():
        root4 = Toplevel()
        root4.title('Top Ten Tennis')
        root4.geometry("700x600")
        fileName= StringVar()
        #Label(root4, text="Izaberite fajl", font=("Arial", 15)).grid(row=0, column=0,  padx=10, pady=10)
        #fajl = Entry(root4, textvariable=fileName, width=30)
        #fajl.grid(row=1, column=0,  padx=10, pady=10)
        Button(root4, text="Izaberi fajl", bg='#6f6', font=("Arial", 13), command= lambda: izaberi(fileName)).grid(row=2, column=0,  padx=10, pady=10)
        text_area = st.ScrolledText(root4, width=50, height=2, font=("Arial", 12))
        text_area.grid(column=0, row=4, pady=50, padx=50)

        def sacuvajPoruku(poruka, fajl):
            fajl = filedialog.asksaveasfilename(defaultextension=".txt")
            if not fajl:
                fajl="fajl"
            try:
                if  isinstance(poruka, bytes):
                    poruka=poruka.decode('ascii')
                with open(fajl+".txt", 'w') as f:
                    f.write(poruka)
                    messagebox.showinfo("Uspesno", "Poruka je uspesno sacuvana.")
            except Exception:
                messagebox.showinfo("Greska", "Nije moguce sacuvati poruku, nesite ponovo podatke.")

        def izaberi(fileName):
            fileName = "userA/poruka.txt"
            fileName = filedialog.asksaveasfilename(defaultextension=".txt")

            flag = True
            poruka = "Kratka poruka."
            try:
                with open(fileName, 'rb') as f:
                    primljenaPoruka = f.read().decode('ascii').split('\n')

                    radixDone = 0
                    signDone=0
                    compressDone=0
                    encrDone=0

                    text = primljenaPoruka[4]
                    sign = None
                    myflags = "1111"+primljenaPoruka[0][4:-1]
                    if (primljenaPoruka[0][3] == "0"):
                        text = decode_base64_message(primljenaPoruka[4])
                        radixDone = 1
                        print("Uradjen radix: " + str(text))



                    # Potpis kompresija enkripicija  radix aes/cast neca
                    if (primljenaPoruka[0][2] == "0"):
                        for idB in PrivateKeyRing:
                            if PrivateKeyRing[idB][0].keyID == primljenaPoruka[2][:-1]:

                                # from tkinter import simpledialog
                                lozinka = simpledialog.askstring("Lozinka", "Unesite lozinku privatnog kljuca: ",
                                                                 show='*')
                                password = calculate_sha1(lozinka)  # ------------------------------------------------------------------------------------
                                if (password != PrivateKeyRing[idB][0].password):
                                    flag = 0
                                    messagebox.showinfo("Greska", "Lozinka nije tacna.")
                                    return
                                if primljenaPoruka[0][5] == "1":
                                    key = PrivateKeyRing[idB][0].privateKey
                                else:
                                    key = PrivateKeyRing[idB][0].privateGamal
                                if not isinstance(text, bytes):
                                    text = eval(text)
                                if primljenaPoruka[0][4] == "0" and primljenaPoruka[0][5] == "1":  # RSA AND AES
                                    kljuc = eval(primljenaPoruka[3][:-1])
                                    sessionKey = decrypt(kljuc, key)
                                    sessionKey = eval(sessionKey.encode('utf-8'))
                                    text = aes128Decrypt(sessionKey, text)
                                    encrDone = 1
                                elif primljenaPoruka[0][4] == "1" and primljenaPoruka[0][5] == "1":  # RSA AND CAST
                                    kljuc = eval(primljenaPoruka[3][:-1])
                                    sessionKey = decrypt(kljuc, key)
                                    sessionKey = eval(sessionKey.encode('utf-8'))
                                    text = cast5Decrypt(sessionKey, text)
                                    encrDone = 1
                                elif primljenaPoruka[0][4] == "0" and primljenaPoruka[0][5] == "0":  # ELGAMAL AND aes
                                    parametri = primljenaPoruka[3][1:-2]
                                    parametri = parametri.split(",")
                                    c1 = int(parametri[0])
                                    c2 = int(parametri[1])
                                    x = key[1]
                                    p = key[0]
                                    sessionKey = decryptElgamal(c1, c2, x, p)
                                    # text = eval(primljenaPoruka[4].encode('utf-8'))
                                    sessionKey = sessionKey.to_bytes(16, "big")
                                    text = aes128Decrypt(sessionKey, text)
                                    encrDone = 1
                                else:
                                    parametri = primljenaPoruka[3][1:-2]
                                    parametri = parametri.split(",")
                                    c1 = int(parametri[0])
                                    c2 = int(parametri[1])
                                    x = key[1]
                                    p = key[0]
                                    sessionKey = decryptElgamal(c1, c2, x, p)
                                    sessionKey = sessionKey.to_bytes(16, "big")
                                    text = cast5Decrypt(sessionKey, text)
                                    encrDone=1
                                break
                                #myflags[2] = "0"
                    if (primljenaPoruka[0][1] == "0" and flag):
                        if (text[-1] == '\r'):
                            text = text[:-1]
                        if not isinstance(text, bytes):
                            text = eval(text)
                        text1 = decompress_message(text).split('\n')
                        text = text1[0]
                        compressDone = 1

                        try:
                            sign = eval(text1[1].encode('utf-8'))

                        except Exception:
                            sign = 0


                    #Potpis
                    if (primljenaPoruka[0][0] == "0" and flag):
                        for idA in PublicKeyRing:  # -----------------------------------------------------------------------------------------Public
                            if PublicKeyRing[idA][0].keyID == primljenaPoruka[1][:-1] and PublicKeyRing[idA][0].isRsa:
                                if not sign:
                                    if isinstance(text, bytes):
                                        text = text.decode('utf-8')
                                    if type(text) == str and text[0] == "b" and (text[1] == "'" or text[1] == '"'):
                                        text = eval(text)
                                        text = text.decode('utf-8')
                                    text = text.split('\n')
                                    sign = text[1]
                                    text = text[0]
                                key = PublicKeyRing[idA][0].publicKey
                                key1=PrivateKeyRing[idA][0].privateKey
                                if not isinstance(sign, bytes):
                                    sign = eval(sign)
                                if (text[-1] != '\n'):
                                    text = text + "\n"
                                msgHash = calculate_sha1(text)
                                decr = decrypt(sign, key)
                                decr = decrypt(sign, key1)

                                if (msgHash == decr):
                                    flag = 1
                                    signDone=1
                                    messagebox.showinfo("Uspesno", "Potpis je validan.")
                                else:
                                    flag = 0
                                    messagebox.showinfo("Greska", "Potpis nije validan.")
                                    return
                            if PublicKeyRing[idA][0].keyID == primljenaPoruka[1][:-1] and not PublicKeyRing[idA][
                                0].isRsa:
                                if not sign:
                                    if isinstance(text, bytes):
                                        text = text.decode('utf-8')
                                    if type(text) == str and text[0] == "b" and (text[1] == "'" or text[1] == '"'):
                                        text = eval(text)
                                        text = text.decode('utf-8')
                                    text = text.split('\n')
                                    sign = text[1]
                                    text = text[0]
                                key = PublicKeyRing[idA][0].publicKey
                                if not isinstance(sign, bytes):
                                    sign = eval(sign)
                                if (text[-1] != '\n'):
                                    text = text + "\n"
                                msgHash = calculate_sha1(text)
                                verify1 = verifyDSA(text.encode('utf-8'), key, sign)
                                if (verify1):
                                    flag = 1
                                    messagebox.showinfo("Uspesno", "Potpis je validan.")
                                    signDone=1
                                else:
                                    flag = 0
                                    messagebox.showinfo("Greska", "Porpis nije validan.")
                                    return
                                break

                    if (int(primljenaPoruka[0][0]) == signDone) or (int(primljenaPoruka[0][1]) == compressDone) or (int(primljenaPoruka[0][2]) == encrDone) or(int(primljenaPoruka[0][3]) == radixDone):
                       flag=0

                    if flag:
                        if type(text) == str and text[0] == "b" and (text[1] == "'" or text[1] == '"'):
                            text = eval(text)
                            text = text.decode('utf-8')
                        fName = StringVar()
                        text_area.insert(tk.INSERT, text)
                        text_area.configure(state='disabled')
                        #Label(root4, text="Unesite naziv fajla", font=("Arial", 20)).grid(row=5, column=0)
                        Button(root4, text="Sacuvaj poruku", font=("Arial", 13),
                               command=lambda: sacuvajPoruku(text, fName.get())).grid(row=7, column=0)
                        #fajl = Entry(root4, textvariable=fName, width=30)
                        #fajl.grid(row=6, column=0)
                    else:
                        messagebox.showinfo("Greska", "Greska prilikom citanja poruke.")

                    f.close()
            except Exception as e:
                print(str(e))
                messagebox.showinfo("Greska", "Greska prilikom citanja poruke ili fajla.")

        root4.mainloop()





    #end
    #https://www.thesecuritybuddy.com/cryptography-and-python/how-to-implement-the-dsa-signature-creation-and-verification-algorithm-in-python/



    root2.mainloop()





generateWindow()