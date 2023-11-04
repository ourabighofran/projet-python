#projet_python :
ce projet se compose des étapes d'enregistrement et de chiffrement et déchiffrement des données comme il est decrit si dessous:

1- Enregistrement
    1-a Email (devrait être valide (Regular Expression)
    1-b Pwd (tapé d'une façon invisible A pwd qui 
            est composé par 1 majuscule, 
            1 lettre minuscule, 1 chiffre, 
            1 car. Special et de taille 8)
   Ind. Email:Login vont être enregistrés ds un 
   fichier Enregistrement.txt         

2- Authentification
    2-a : Email
    2-b : Pwd 
    Si les credentials existent ds l'enregistrement.txt
    un menu s'affichera (Voir plus loin) sinon il est 
    amené à s'enregistrer 
    Ind. Le menu, une fois authentifié,est comme suit : 
        A- Donnez un mot à haché (en mode invisible)
                a- Haché le mot par sha256 
                b- Haché le mot en générant un salt (bcrypt)
                c- Attaquer par dictionnaire le mot inséré. 

              d- Revenir au menu principal 

       B- Chiffrement (RSA)
                a- Générer les paires de clés dans un fichier 
                b- Chiffrer un message de votre choix par RSA
                c- Déchiffrer le message (b) 

              d- Signer un message de votre choix par RSA

              e- Vérifier la signature du message (d)

              f- Revenir au menu principal  

        C- Certificat (RSA)
                a- Générer les paires de clés dans un fichier 
                b- Générer un certificat autosigné par RSA
                c- Chiffrer un message de votre choix par ce certificat

              d- Revenir au menu principal
