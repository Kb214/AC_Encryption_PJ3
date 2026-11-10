
"""
What To Do: 


1. Generate Public and Private Key Using RSA
    - Each member has a public and private key
    - info will be stored in ca.txt files:
        - EX: Alice_ca.txt
        __________

        !!FORMAT!!
        Public Key
        Private Key
        Attributes
        ___________

    

2. Request PUBLIC KEY of each member from those files ^^^



3. Using the PUBLIC KEY: 
    - Generate symmetric PRIVATE KEY [named K] with AES
    - request everyones RSA public key
    - Encrypts K for each user
    - create files: 
        Alice_sharekey.txt

        Funtion: 
            RSA.Encrypt(Publickey_Alice, K)

    - be able to print out these files
    - User will be able to decrypt K using private RSA key



4. Using K
    - encrypt plaintext.txt --> plaintext.txt.enc
    - Process: 
        includes policy 
        this files is only accessed by people satisfy this condition:

            (ATT1 AND ATT2) OR (ATT3 AND ATT4 AND ATT5)

            which are basically Alice Bob Emmy and Daisy

        
5. When trying to decrypt the plaintext.txt.enc file: 
    - authorized people --> content of plaintext and K
    - unauthorized people --> Not authorized



6. Revoking attributes: 
    - Do this for Emmy
        - take away ATT1
        - This change will go to a file [revocation_log.txt]
            
            !!FORMAT!!
            _______________________________

            <timestamp>, Emmy, Att1 REVOKED
            _______________________________

7. When revoke the attribute: 
    - generate a new AES key [name K]
    - rencrypts plain.txt to plain.txt.enc
    - old key is destroyed
    - the sharekey.txt files are now encrypted with the new key
        - ONLY for people who satisfy the policy
        - The ones who don't WILL NOT have a sharekey files

        

8. List of sharekey files that exist after roations MUST BE PRINTED

9. Show that new plaintext.txt.enc is different

"""


from Crypto import Random

from Crypto.Cipher import AES

import base64

import rsa




def pad(s):
  return s + b"\0" * (AES.block_size - len(s) % AES.block_size)


#ENCRYPTING AND DECRYPTING AES FUNCTIONS
#FOR SYMMETRIC PRIVATE KEY  K

def encrypt(message, key, key_size=256):

  message = pad(message)

  iv = Random.new().read(AES.block_size)

  cipher = AES.new(key, AES.MODE_CBC, iv)

  return iv + cipher.encrypt(message)



def decrypt(ciphertext, key):

  iv = ciphertext[:AES.block_size]

  cipher = AES.new(key, AES.MODE_CBC, iv)

  plaintext = cipher.decrypt(ciphertext[AES.block_size:])

  return plaintext.rstrip(b"\0")


#USING RSA TO ENCRYPT PUBLIC AND PRIVATE KEYS FOR USERS


if __name__== "__main__":

  (pubkeyA, privkeyA) = rsa.newkeys(1024)

  (pubkeyB, privkeyB) = rsa.newkeys(1024)

  (pubkeyC, privkeyC) = rsa.newkeys(1024)

  (pubkeyD, privkeyD) = rsa.newkeys(1024)

  (pubkeyE, privkeyE) = rsa.newkeys(1024)

  #msg = b'A message for signing'


  key = b'123cyberarena123'
  print("The entered key is:", key)


  Alice_sharkey = rsa.encrypt(key, pubkeyA)

  Bob_sharkey = rsa.encrypt(key, pubkeyB)

  Charlie_sharkey = rsa.encrypt(key, pubkeyC)

  Daisy_sharkey = rsa.encrypt(key, pubkeyD)

  Emmy_sharkey = rsa.encrypt(key, pubkeyE)


employees = ["Alice", "Bob", "Charlie", "Daisy", "Emmy"]
pubkey = [pubkeyA, pubkeyB, pubkeyC, pubkeyD, pubkeyE]
privkey = [privkeyA, privkeyB, privkeyC, privkeyD, privkeyE]
sharekey = [Alice_sharkey, Bob_sharkey, Charlie_sharkey, Daisy_sharkey, Emmy_sharkey]


for x, y, z in zip(employees, pubkey, privkey):
  with open(x + "_ca.txt", "w") as f:
    f.write(f"{y}\n")
    f.write (f"{z}\n")
    if x == "Alice":
      f.write("att1 att2\n")
    elif x == "Bob":
      f.write("att1 att3 att4\n")
    elif x == "Charlie":
      f.write("att4 att5\n")
    elif x == "Daisy":
      f.write("att2 att2\n")
    elif x == "Emmy":
      f.write("att1 att2 att3 att4 att5\n")

f.close()

for p,r in zip(employees, sharekey):
  with open(p + "_sharekey.txt", "w") as f:
    f.write(f"{r}\n")

f.close()

employee =  input("which employee key do you want to decrypt?: ")

if employee == "Alice":
  f = open(employee + "_ca.txt")
  f.readline()
  a = f.readline()
  k = rsa.decrypt(Alice_sharkey, a)
  print(k)
  f.close()
#COULD USE DICTIONARY; not using it, too complicated for lookup


#users = { 
  #"userspubkey" : {"Alice" : pubkeyA, "Bob": pubkeyB, "Charlie": pubkeyC, "Daisy": pubkeyD, "Emmy": pubkeyE},
  #"userprivkey" : {"Alice" : privkeyA, "Bob": privkeyB, "Charlie": privkeyC, "Daisy": privkeyD, "Emmy": privkeyE},
  #}

#print("This is Alice's Private Key: ",users["userprivkey"]["Alice"])

#for key, value in users["userspubkey"]:
  #print(key)

#print(employees)
#print(employees[3])

#print(privkeyB)
