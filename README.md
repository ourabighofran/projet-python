import hashlib
import re
import bcrypt
import getpass
import datetime
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.backends import default_backend
from cryptography import x509
from cryptography.x509.oid import NameOID

file1 = open(r"C:\python\enregist.txt", "a")

regex = re.compile(r'([A-Za-z0-9]+[.-_])*[A-Za-z0-9]+@[A-Za-z0-9-]+(\.[A-Z|a-z]{2,})+')

while True:
    email = input("donner votre email: ")
    if re.fullmatch(regex, email):
        print("email valide!")
        break

while True:
    def verifier_mot_de_passe(mot_de_passe):
        if len(mot_de_passe) != 8:
            return False
        if not re.search(r'[A-Z]', mot_de_passe):
            return False
        if not re.search(r'[a-z]', mot_de_passe):
            return False
        if not re.search(r'\d', mot_de_passe):
            return False
        if not re.search(r'[!@#$%^&*()_+{}":;<>,.?~\\-]', mot_de_passe):
            return False
        return True
    
    mot_de_passe_utilisateur = getpass.getpass("Donnez votre mot de passe: ")

    if verifier_mot_de_passe(mot_de_passe_utilisateur):
        print("Mot de passe valide.")
        break
    else:
        print("Mot de passe invalide. Assurez-vous qu'il comporte au moins 1 majuscule, 1 minuscule, 1 chiffre, 1 caractère spécial, et a une longueur de 8 caractères.")

file1.write(email)
file1.write("---")
file1.write(mot_de_passe_utilisateur)
file1.write("\n")
file1.close()

print("votre données est enregistré sur 'enregist.txt' file.")

print("Login!")
log = input("email: ")
pwd = input("password: ")
compare = log + "---" + pwd
file1 = open(r"C:\python\enregist.txt", "r")
for logins in file1:
    if compare == logins.strip():
        print("introuvable")

        while True:
            print("A- Donnez un mot à hacher (en mode invisible)")
            print("B- Chiffrement (RSA)")
            print("C- Certificat (RSA)")
            print("D- Quitter")

            choice = input("Choice : ")

            if choice == 'A':
                text = getpass.getpass("Donnez un mot à hacher: ")
                print("a- Haché le mot par sha256")
                print("b- Haché le mot en générant un salt (bcrypt)")
                print("c- Attaquer par dictionnaire le mot inséré")
                print("d- Revenir au menu principal")

                while True:
                    choice = input("Choice : ")
                    if choice == 'a':
                        hashed_text =hashlib.sha256(text.encode()).hexdigest()
                        print(hashed_text)
                    elif choice == 'b':
                        salt = bcrypt.gensalt()
                        hashed = bcrypt.hashpw(text.encode(), salt)
                        print("Salt:", salt)
                        print("Hashed:", hashed)
                        
                    elif choice == 'c':
                        dictionary = ["mot1", "mot2", "mot3", "mot4", "mot5"]
                        print("Attaquer par dictionnaire")
                        for word in dictionary:
                         hashed_word = hashlib.sha256(word.encode()).hexdigest()
                         if hashed_word == hashed_text:
                             print(f"Mot trouvé dans le dictionnaire : {word}")
                             break
                         
                         else:
                              print("Aucun mot du dictionnaire ne correspond.")
                              break
                        
                    elif choice == 'd':
                        break
                        
                    
            elif choice == 'B':
                print("Chiffrement (RSA)")
                print("a- Générer les paires de clés dans un fichier")
                print("b- Chiffrer un message de votre choix par RSA")
                print("c- Déchiffrer le message (b) ")
                print("d- Signer un message de votre choix par RSA")
                print("e- Vérifier la signature du message (d)")
                print("f- Revenir au menu principal")
                while True:
                     choice = input("Choice : ")
                     if choice == 'a':
                            
                            
                            def generate_key_pair():

                                private_key = rsa.generate_private_key(
                                    public_exponent=65537,
                                    key_size=2048,
                                    backend=default_backend()
                            )
                                public_key = private_key.public_key()
                                return private_key, public_key
                            private_key, public_key = generate_key_pair()
                            print("clé privé:")
                            print(private_key)
                            print("\n clé privé:")
                            print(public_key)
                            file2=open(r"C:\python\keys.txt", "a")
                            file2.write(str(private_key))
                            file2.write("\n")
                            file2.write(str(public_key))
                            file2.write("\n")
                            file2.close()

                            
                           
                     if choice == 'b':
                        message = input("Entrez le message que vous souhaitez chiffrer : ")
    
                        # Chiffrement du message avec la clé publique
                        encrypted_message = public_key.encrypt(
                            message.encode('utf-8'),
                            padding.OAEP(
                             mgf=padding.MGF1(algorithm=hashes.SHA256()),
                             algorithm=hashes.SHA256(),
                            label=None
                          )
                       )
    
                        print("Message chiffré :")
                        print(encrypted_message)
                     
                     if choice == 'c':
                        decrypted_message = private_key.decrypt(
                           encrypted_message,
                           padding.OAEP(
                              mgf=padding.MGF1(algorithm=hashes.SHA256()),
                              algorithm=hashes.SHA256(),
                              label=None
                          )
                       )
    
                        print("Message déchiffré :")
                        print(decrypted_message.decode('utf-8'))
                        
                     if choice == 'd':
                        message_to_sign = input("Entrez le message que vous souhaitez signer : ")

                        # Signature du message avec la clé privée
                        signature = private_key.sign(
                            message_to_sign.encode('utf-8'),
                            padding.PKCS1v15(),
                            hashes.SHA256()
                        )

                        print("Signature générée :")
                        print(signature)


                     if choice == 'e':
                        try: 
                            public_key.verify(
                                signature,
                                message_to_sign.encode('utf-8'),
                                padding.PKCS1v15(),
                                hashes.SHA256()
                            )

                            print("La signature est valide.")
                        except Exception:
                            print("La signature n'est pas valide.")
                     
                     
                     if choice == 'f':
                        break      
            elif choice == 'C':
                print("Certificat (RSA)")
                print(" a- Générer les paires de clés dans un fichier ")
                print(" b- Générer un certificat autosigné par RSA")
                print(" c- Chiffrer un message de votre choix par ce certificat ")
                print(" d- Revenir au menu principal")

                while True:
                  choice = input("Choice : ")
                  if choice == 'a':

                        def generate_key_pair():
                             private_key = rsa.generate_private_key(
                                 public_exponent=65537,
                                 key_size=2048,
                                 backend=default_backend()
                            ) 
                             public_key = private_key.public_key()
                             return private_key, public_key

                        private_key, public_key = generate_key_pair()
                        print("Private Key:")
                        print(private_key)
                        print("\nPublic Key:")
                        print(public_key)
                        file3=open(r"C:\python\certificat.txt", "a")
                        file3.write(str(private_key))
                        file3.write("\n")
                        file3.write(str(public_key))
                        file3.write("\n")
                        file3.close()
                  if choice=='b':
                      

                      
                      # Création du certificat autosigné
                     subject = issuer = x509.Name([
                         x509.NameAttribute(NameOID.COUNTRY_NAME, "italia"),
                         x509.NameAttribute(NameOID.STATE_OR_PROVINCE_NAME, "france"),
                         x509.NameAttribute(NameOID.LOCALITY_NAME, "monaco"),
                         x509.NameAttribute(NameOID.ORGANIZATION_NAME, "mon Organization"),
                         x509.NameAttribute(NameOID.COMMON_NAME, "Mon nom"),
                      ])

                     cert = x509.CertificateBuilder().subject_name(
                        subject
                     ).issuer_name(
                       issuer
                     ).public_key(
                       private_key.public_key()
                     ).serial_number(
                       x509.random_serial_number()
                     ).not_valid_before(
                       datetime.datetime.utcnow()
                        
                     ).not_valid_after(
                       datetime.datetime.utcnow() + datetime.timedelta(days=365)
                     ).sign(private_key, hashes.SHA256(), default_backend())
                         
                  if choice =='c' :
                        public_key = cert.public_key()
                        message = input("Entrez le message que vous souhaitez chiffrer : ")
        
                            # Chiffrement du message avec la clé publique
                        encrypted_message = public_key.encrypt(
                                message.encode('utf-8'),
                                padding.OAEP(
                                 mgf=padding.MGF1(algorithm=hashes.SHA256()),
                                 algorithm=hashes.SHA256(),
                                label=None
                            )
                         )
        
                        print("Message chiffré :")
                        print(encrypted_message)
                
                  if choice =="d":
                    break     
                   
                 
                


            elif choice == 'D':
                 print("Quitter")
                 break

        break
else:
    print("introuvable")
    file1 = open(r"C:\python\enregist.txt", "a")
    file1.write(log)
    file1.write("---")
    file1.write(pwd)
    file1.write("\n")
    file1.close()
    print("votre données est enregisté sur ' file.")
    
