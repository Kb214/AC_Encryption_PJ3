
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
        this file is only accessed by people satisfy this condition:

            (ATT1 AND ATT2) OR (ATT3 AND ATT4 AND ATT5)

            which are basically Alice Emmy and Daisy

        
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

from datetime import datetime, timezone
from Crypto import Random

from Crypto.Cipher import AES

import base64

import rsa

import os 


#FUNCTIONS FOR ENCRYPTION AND DECRYPTION

def pad(s):
  return s + b"\0" * (AES.block_size - len(s) % AES.block_size)

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




def outputShareFile(employeelist):
  for emp in employeelist:
    print(f"{emp}_sharekey2.txt\n")



def writeEmployeeFiles(keylist, attriblist):
    for user, definition in keylist.items():
        with open(f"{user}_ca2.txt", "w") as f:
            f.write(f"{keylist[user]["pub"]}\n")
            f.write(f"{keylist[user]["priv"]}\n")


    for user, definition in attriblist.items():
        with open(f"{user}_ca2.txt", "a") as f:
            yes_attributes = [
                attribute
                for attribute, value in attriblist[user].items()
                if value == "yes"
            ]
            f.write(f"{" ".join(yes_attributes)}")

    for user, definition in keylist.items():
      with open(f"{user}_sharekey.txt", "w") as f:
         f.write(f"{keylist[user]["share"]}")


        
def encryptPlainTxt(usersecret):
  with open("plaintext.txt","w") as f:
    f.write("Only Alice, Emmy, and Daisy will be able to see this file. If you see this file and are not autorize to do so, you will be fired.")

  with open("plaintext.txt", "rb") as f:
    data = f.read()

  new_encryption = encrypt(data, usersecret)

  with open("plaintext.txt.enc", "wb") as f:
    f.write(new_encryption)

  with open("plaintext.txt.enc", "rb") as f:
    text = f.read()

  decrypted = decrypt(text, usersecret)
  print(decrypted, "\n")


      
      
#def decryptPlainTxt(usersecret): 
 
  #with open("plaintext.txt.enc", "rb") as f:
   # text = f.read()

  #decrypted = decrypt(text, usersecret)
  #print(decrypted, "\n") 
      

def revokeUA(revokeUser, revokeAttrib, attriblist, keylist):
  now = datetime.now()
  readable_ts = now.strftime("%Y-%m-%d %H:%M:%S")

  attriblist[revokeUser].update({revokeAttrib : "no" })

  with open("revocation_log.txt","a") as f:
    f.write(f"{readable_ts}, {revokeUser}, {revokeAttrib} REVOKED")

  with open(f"{revokeUser}_ca.txt","w") as f:
    f.write(f"{keylist[revokeUser]["pub"]}\n")
    f.write(f"{keylist[revokeUser]["priv"]}\n")
    if revokeUser in attriblist:
      for attribute, value in attriblist[revokeUser].items():
        if value == "yes":
          f.write(f"{attribute} ")


  


def rotate(employeesatt):
  new_k = os.urandom(32)

  with open("plaintext.txt", "rb") as f:
    plain = f.read()

  rotation = encrypt(plain, new_k)

  with open("plaintext.txt.enc", "wb") as f:
    f.write(rotation)

  for employee in employeesatt: 
    sharekey = f"{employee}_sharekey.txt"

    if((employeesatt[employee]["attr1"] == "yes" and employeesatt[employee]["attr2"] == "yes") or (employeesatt[employee]["attr3"] == "yes" and employeesatt[employee]["attr4"] == "yes" and employeesatt[employee]["attr5"] == "yes") ):

      rotation = rsa.encrypt(new_k, userkeys[employee]["pub"])

      with open(sharekey, "wb") as f:
        f.write(rotation)
    
    elif os.path.exists(sharekey):
        os.remove(sharekey)


if __name__== "__main__":

  (pubkeyA, privkeyA) = rsa.newkeys(1024)

  (pubkeyB, privkeyB) = rsa.newkeys(1024)

  (pubkeyC, privkeyC) = rsa.newkeys(1024)

  (pubkeyD, privkeyD) = rsa.newkeys(1024)

  (pubkeyE, privkeyE) = rsa.newkeys(1024)

  
  

  msg = b'A message for signing'


  key = b'123cyberarena123'
  #print("The entered key is:", key)


  Alice_sharkey = rsa.encrypt(key, pubkeyA)

  Bob_sharkey = rsa.encrypt(key, pubkeyB)

  Charlie_sharkey = rsa.encrypt(key, pubkeyC)

  Daisy_sharkey = rsa.encrypt(key, pubkeyD)

  Emmy_sharkey = rsa.encrypt(key, pubkeyE)



#STORAGE OF USERS, KEYS, AND ATTRIBUTES

employees = ["Alice", "Bob", "Charlie", "Daisy", "Emmy"]

userkeys={
  "Alice" : {"priv" : privkeyA, "pub":pubkeyA, "share": Alice_sharkey},
  "Bob" : {"priv" : privkeyB, "pub":pubkeyB, "share": Bob_sharkey},
  "Charlie" : {"priv" : privkeyC, "pub":pubkeyC, "share": Charlie_sharkey},
  "Daisy" : {"priv" : privkeyD, "pub":pubkeyD, "share": Daisy_sharkey},
  "Emmy" : {"priv" : privkeyE, "pub":pubkeyE, "share": Emmy_sharkey},

}

userattrib = {
  "Alice" : {"attr1": "yes", "attr2": "yes", "attr3": "no", "attr4": "no", "attr5": "yes"},
  "Bob" : {"attr1": "yes", "attr2": "no", "attr3": "yes", "attr4": "yes", "attr5": "no"},
  "Charlie" : {"attr1": "no", "attr2": "no", "attr3": "no", "attr4": "yes", "attr5": "yes"},
  "Daisy" : {"attr1": "yes", "attr2": "yes", "attr3": "no", "attr4": "no", "attr5": "no"},
  "Emmy" : {"attr1": "yes", "attr2": "yes", "attr3": "yes", "attr4": "yes", "attr5": "yes"},
}






print("\n|Welcome to the Encryption File Access Control System|\n|====================================================|\n")

i = 0
while i < 5:
  writeEmployeeFiles(userkeys, userattrib)
  print("=====================\nWhat would you like to do?\n")
  print(" 1.print out all of the sharekey files\n 2.print the decrypted data of the plaintext file.\n 3.print the encrypted data of plaintext file\n 4.Revoke employee key\n 5.EXIT\n=====================")
  user_in = input("Choice:")
  

  if user_in == "1":
    print("\n========All Sharekey Files:=========\n")
    outputShareFile(employees) 
  elif user_in == "2":

    employee = input("\nWhich user credential you want to use to decrypt the plaintext.txt.enc file? : ").strip()

    if(employee in userattrib and ((userattrib[employee]["attr1"] == "yes" and userattrib[employee]["attr2"] == "yes") or (userattrib[employee]["attr3"] == "yes" and userattrib[employee]["attr4"] == "yes" and userattrib[employee]["attr5"] == "yes")) ):
      print(f"{employee} approved!\n")

      print("==========Decrypted Plaintext File:==========\n")
      new_secret = rsa.decrypt(userkeys[employee]["share"], userkeys[employee]["priv"])
      encrytext = encryptPlainTxt(new_secret)
    elif employee in userattrib:
       print(f"{employee} is NOT authorized.\n")
    else: 
       print("Uknoown. Enter Valid name.\n")

  elif user_in == "3":
    with open("plaintext2.txt.enc", "rb") as f:
      encryData = f.read()
    print(encryData, "\n")

  elif user_in == "4":
    revoke = input("whose attribute do you want to revoke?: ")
    at = input(f"which attribute you want to revoke for {revoke}?: " )

    revokeUA(revoke, at, userattrib, userkeys)

    print("===========Remaining users who can decrypt plaintext:============\n")
    for user, attrib in userattrib.items(): 
      if((attrib["attr1"] == "yes" and attrib["attr2"] == "yes") or (attrib["attr3"] == "yes" and attrib["attr4"] == "yes" and attrib["attr5"] == "yes") ):
        print(f"{user} can decrypt plaintext file.\n")
      else: 
        print(f"{user} cannot decrypt plaintext file.\n")

    rotate(userattrib)
    
  elif user_in == "5":
    break 

  else:
    print("\n=====++ !! |invalid answer. Try again.| !! ++=====\n")

