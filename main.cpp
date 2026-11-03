#include<iostream>

/*

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
        this files is only access by people satisfy this condition:

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



*/

int main(){




    return 0;
}