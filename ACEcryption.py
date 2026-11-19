from Crypto import Random

from Crypto.Cipher import AES

import base64

import rsa

import os 




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


#making sharkey files and ca files
employees = ["Alice", "Bob", "Charlie", "Daisy", "Emmy"]
pubkey = [pubkeyA, pubkeyB, pubkeyC, pubkeyD, pubkeyE]
privkey = [privkeyA, privkeyB, privkeyC, privkeyD, privkeyE]
sharekey = [Alice_sharkey, Bob_sharkey, Charlie_sharkey, Daisy_sharkey, Emmy_sharkey]

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
  with open(p + "_sharekey.txt", "w") as b:
    b.write(f"{r}\n")

b.close()

#decryption of employee key

employee =  input("which employee key do you want to decrypt?: ")

if employee == "Alice":
  d = open(employee + "_ca.txt")
  d.readline()
  a = d.readline()
  k = rsa.decrypt(Alice_sharkey, privkeyA)
  print(k)
  d.close()


#creating plaintext file and encrypting/decrypting it !!!![I DID THIS WRONG; REDO IT]!!!!

with open("plaintext.txt","w") as z:
  z.write("Only Alice, Bob, Emmy, and Daisy will be able to see this file. If you see this file and are not autorize to do so, you will be fired.")

new_secret = rsa.decrypt(Alice_sharkey, privkeyA)
with open("plaintext.txt", "rb") as f:
  data = f.read()

new_encryption = encrypt(data, new_secret)

with open("plaintext.txt.enc", "wb") as f:
  f.write(new_encryption)

with open("plaintext.txt.enc", "rb") as f:
  text = f.read()

decrypted = decrypt(text, new_secret)
print(decrypted)

"""
z = open("plaintext.txt","rb")
data = z.read()
print(data)
z.close()

encrypted_data = encrypt(data, k)

f2 = open("plaintext.txt.enc", "wb")
f2.write(encrypted_data)


f2.close()


"""

#attribute based decryption: 

for user, attrib in userattrib.items(): 
  if((attrib["attr1"] == "yes" and attrib["attr2"] == "yes") or (attrib["attr3"] == "yes" and attrib["attr4"] == "yes" and attrib["attr5"] == "yes") ):
    print(f"{user} can decrypt plaintext file.\n")
  else: 
    print("employees cannot decrypt plaintext file.\n")


#revoking attributes: Emmy, write into file and change attributes, made revocation log file

revoke = input("whose attribute do you want to revoke?: ")
at = input(f"which attribute you want to revoke for {revoke}?: " )

from datetime import datetime, timezone

now = datetime.now()
readable_ts = now.strftime("%Y-%m-%d %H:%M:%S")

utc_ts = datetime.now(timezone.utc).isoformat()


userattrib[revoke].update({at : "no" })

with open("revocation_log.txt","w") as f:
  f.write(f"{readable_ts}, {revoke}, {at} REVOKED")

print(userkeys[revoke]["pub"])
print(userkeys[revoke]["priv"])

if revoke in userattrib:
  yes_attributes = [
    attribute
    for attribute, value in userattrib[revoke].items()
    if value == "yes"
  ]
  print(" ".join(yes_attributes))
else:
  print(f"unknown user: {revoke}")


for user, attrib in userattrib.items(): 
  if((attrib["attr1"] == "yes" and attrib["attr2"] == "yes") or (attrib["attr3"] == "yes" and attrib["attr4"] == "yes" and attrib["attr5"] == "yes") ):
    print(f"{user} can decrypt plaintext file.\n")
  else: 
    print("employees cannot decrypt plaintext file.\n")



with open(f"{revoke}_ca.txt","w") as f:
  f.write(f"{userkeys[revoke]["pub"]}\n")
  f.write(f"{userkeys[revoke]["priv"]}\n")
  if revoke in userattrib:
    for attribute, value in userattrib[revoke].items():
      if value == "yes":
        f.write(f"{attribute} ")
  

#key rotation 

"""
7. When revoke the attribute: 
    - generate a new AES key [name K]
    - rencrypts plain.txt to plain.txt.enc
    - old key is destroyed
    - the sharekey.txt files are now encrypted with the new key
        - ONLY for people who satisfy the policy
        - The ones who don't WILL NOT have a sharekey files

"""


new_k = os.urandom(32)

with open("plaintext.txt", "rb") as f:
  plain = f.read()

rotation = encrypt(plain, new_k)

with open("plaintext.txt.enc", "wb") as f:
  f.write(rotation)

for employee in employees: 
  sharekey = f"{employee}_sharekey.txt"

  if((userattrib[employee]["attr1"] == "yes" and userattrib[employee]["attr2"] == "yes") or (userattrib[employee]["attr3"] == "yes" and userattrib[employee]["attr4"] == "yes" and userattrib[employee]["attr5"] == "yes") ):

    rotation = rsa.encrypt(new_k, userkeys[employee]["pub"])

    with open(sharekey, "wb") as f:
      f.write(rotation)
    
  elif os.path.exists(sharekey):
      os.remove(sharekey)

print("The sharekey files that remain:")
for employee in employees: 
  if os.path.exists(f"{employee}_sharekey.txt"):
    print(f"{employee}_sharekey.txt")

#print(userattrib)

#for p in employees:
  #with open(p + "_ca.txt", "r") as f:
    #f.readline()
    #f.readline()
    #att = f.readline()
    #print(att)
    #if( att == "att1" and att == "att2" ) or (att == "att3 att4 att5"):
      #print(f"{p} can decrypt the plaintext file\n")
    #else:
      #print("Employee cannot decrypt the plain text file.\n")






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
