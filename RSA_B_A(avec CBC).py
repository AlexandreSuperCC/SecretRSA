# -*- coding: utf-8 -*-
"""
Created on Fri Apr 17 13:44:40 2020

@author: Yuan Cao
"""
import hashlib
import binascii
import random

###### ici c'est les autres methodes pour obtenir les résultats, on ne les utilise pas ######
# def home_mod_expnoent(a,b,c):
#     a=a%c
#     ans=1
#     while b!=0:
#         if b&1:
#             ans=(ans*a)%c
#         b>>=1
#         a=(a*a)%c
#     return ans

# def home_ext_euclide(y,b): #algorithme d'euclide étendu pour la recherche de l'exposant secret
#     n = 1
#     q = [0]; u = [0]*3
#     left=y; right=b     
#     while right % left != 0:            
#         if n == 1: #lorsqu'il n'y pas d'élément dans la liste
#             q[0] =right//left
#             n+=1
#             mid = left
#             left = right % left
#             right = mid
#         else:
#             q.append(right//left)
#             mid = left
#             left = right % left
#             right = mid
#     q.append(right//left)
#     u[0]=1;u[1]=0
#     n = len(q)
#     for i in range(2, n+1):          
#         u[i] = u[i-2] - q[i-2] * u[i-1]  #ici c'est q[i-2] pas i-1
#         u.append(0)
#     u.pop()
#     return u[i] % y
###### ici c'est les autres methodes pour obtenir les résultats, on ne les utilise pas ######

###### ici c'est la partie de home_mod_expnoent CR_Theorem home_ext_euclide ######

def home_mod_expnoent(x,y,n): #exponentiation modulaire
    num_b = str(bin(y))
    tab_l = list(num_b) #ici inclure '0x' 
    tab = tab_l[2:] #commencer par l'élément après '0x'
    tab.reverse()
    length = len(tab) #longeur de tab
 
    r1 = 1
    r2 = x
    
    for i in range(0, length):
        if tab[i] == '1':
            r1 = r1 * r2 % n
        r2 = r2 * r2 % n            
    return r1

def CR_Theorem(c,d,n1,n2): #Chinese remainder theorem
      if(n1 <= n2):
          xi = n1
          xj = n2
      else:
          xi = n2
          xj = n1 
      q = xi
      p = xj
      q_inverse = home_ext_euclide(p, q)
      dq = d % (q-1)
      dp = d % (p-1)
      
      mq = home_mod_expnoent(c, dq, q)
      mp = home_mod_expnoent(c, dp, p)

      h = ((mp - mq)*q_inverse) % p
      m = (mq + h * q) % (n1*n2)
      return m

def home_ext_euclide(a,b): #algorithme d'euclide étendu pour la recherche de l'exposant secret
    (r, nouvr, t, nouvt) = (a, b, 0, 1)
    
    while(nouvr > 1) : 
        q = (r//nouvr)
        (r, nouvr, t, nouvt) = (nouvr, r%nouvr, nouvt, t-(q*nouvt))
        
    return nouvt % a

###### ici c'est la partie de home_mod_expnoent CR_Theorem home_ext_euclide ######

###### ici c'est la partie de Mode chiffrement par bloc ######
# le maximum nombre de caracteres est 278

def get_vec_ini():
    vec_ini = [1]#creer le tableau avec le premier nombre 1, parce que si le premier est 0, on va le perdre dans la transformatin après
    i = 1
    while(i<100):
        i = i + 1
        vec_ini.append(random.randint(0, 1))#mettre le nombre aléatoir dans le tableau l'un après l'autre
    vec_int = int(''.join(str(i) for i in vec_ini))#transformer le tableau en un int(par exemple [1,0,1,0]=>1010)  
    return vec_int

def getBloc_chif(num_sec):#ici pour avoir la même taille de chaque bloc on met tous 0 pour le reste

    num_sec=str(num_sec)
    list_b=list(num_sec)
    list_len = len(list_b)#obtenir le longeur de message(par exemple 4232424=>7 elements)

    num_bloc=0
    num_in_bloc=0
    if(list_len%100==0):                                                #par exemple, si length=100, on a besoin 1 bloc
        bloc = [['0' for i in range(100)] for j in range(list_len//100)]#mais list_len//100+1=2, donc il y a un bloc inutile
    else:                                                               
        bloc = [['0' for i in range(100)] for j in range(list_len//100+1)]#initialisation de bloc avec tous '0', on obtient
                                                                          #par exemple [['0','0',...],['0','0',...],['0','0',...]]
    i = 0
    while(i<list_len):
        if(num_in_bloc < 100):
            bloc[num_bloc][num_in_bloc] = list_b[i]#mettre les éléments dans chaque bloc
            num_in_bloc = num_in_bloc + 1
            i = i + 1
        else:
            num_in_bloc = 0#nouveau bloc si ce bloc est plein(100 éléments)
            num_bloc = num_bloc + 1
    bloc[num_bloc] = bloc[num_bloc][0:num_in_bloc]#supprimer les element "0" dans le dernier bloc, parce que
                                                  #dans le chiffrement 1000 et 1 est totalement différent
    for i in range(num_bloc+1):                     #Dans chaque grand bloc, transformer des sous-blocs avec les éléments string en un int   
        bloc[i] = int(''.join(i1 for i1 in bloc[i]))#par exemple [['3','9',...],['6','3',...],['1','2',...]] => [39..., 63..., 12...]

    return bloc

def CBC_chiffrement(vec_ini, num_sec, e, n1, n2):
    bloc_secret = []

    bloc = getBloc_chif(num_sec)#obtenir les blocs avec la même taille
    for i in range(len(bloc)):
        if(i==0):
            bloc_secret.append(CR_Theorem(vec_ini^bloc[0], e, n1, n2))
        else:
            bloc_secret.append(CR_Theorem(bloc_secret[i-1]^bloc[i], e, n1, n2))

 
    chif_num = int(''.join(str(i1) for i1 in bloc_secret))#transformer des blocs avec les éléments int en un int 
                                                          #par exemple [42...,53...,12...] => 42...53...12...
    print("voici le message chiffré avec la publique d'Alice : ")
    print(chif_num)
    return bloc_secret#retourner les blocs de secret pour que l'on puisse les utiliser directement dans le déchiffrement

def CBC_dechiffrement(vec_ini, bloc_secret, d, n1, n2):
    bloc_claire = []

    for i in range(len(bloc_secret)):
        if(i==0):
            bloc_claire.append(vec_ini^CR_Theorem(bloc_secret[0], d, n1, n2))
        else:
            bloc_claire.append(CR_Theorem(bloc_secret[i], d, n1, n2)^bloc_secret[i-1])
 
    dechif_num = int(''.join(str(i1) for i1 in bloc_claire))#transformer des blocs avec les éléments int en un int
                                                            #par exemple [42...,53...,12...] => 42...53...12...
    return dechif_num

###### ici c'est la partie de Mode chiffrement par bloc ######

###### ici c'est la reste ######

def home_pgcd(a,b): #recherche du pgcd
    if(b==0): 
        return a 
    else: 
        return home_pgcd(b,a%b)

def home_string_to_int(x): # pour transformer un string en int
    z=0
    for i in reversed(range(len(x))):
        z=int(ord(x[i]))*pow(2,(8*i))+z
    return(z)

def home_int_to_string(x): # pour transformer un int en string
    txt=''
    res1=x
    while res1>0:
        res=res1%(pow(2,8))
        res1=(res1-res)//(pow(2,8))
        txt=txt+chr(res)
    return txt

def mot10char(): #entrer le secret
    secret=input("donner un secret : ")
    while (len(secret)>278):
        secret=input("c'est beaucoup trop long, <= 278 caractères S.V.P : ")
    return(secret)
    
#voici les éléments de la clé d'Alice

vec_ini = get_vec_ini()#obtenir le vecteur d'initialisation 
x1a=385883505263904262700319888676738759825335809073158524579573 #p
x2a=114020066328360809649388670971127947593560289474839477363299 #q
na=x1a*x2a  #n
phia=((x1a-1)*(x2a-1))//home_pgcd(x1a-1,x2a-1)
ea=17 #exposant public
da=home_ext_euclide(phia,ea) #exposant privé
#voici les éléments de la clé de bob
x1b=398944470630781770864965446764356139009963267708401702564689 #p
x2b=238971070442986483733495158769223106294207366030450245084641 #q
nb=x1b*x2b # n
phib=((x1b-1)*(x2b-1))//home_pgcd(x1b-1,x2b-1)
eb=23 # exposants public
db=home_ext_euclide(phib,eb) #exposant privé


print("Vous êtes Bob, vous souhaitez envoyer un secret à Alice")
print("voici votre clé publique que tout le monde a le droit de consulter")
print("n =",nb)
print("exposant :",eb)
print("voici votre précieux secret")
print("d =",db)
print("*******************************************************************")
print("Voici aussi la clé publique d'Alice que tout le monde peut conslter")
print("n =",na)
print("exposent :",ea)
print("*******************************************************************")
print("il est temps de lui envoyer votre secret ")
print("*******************************************************************")
x=input("appuyer sur entrer")
secret=mot10char()
print("*******************************************************************")


print("voici la version en nombre décimal de ",secret," : ")
num_sec=home_string_to_int(secret)
print(num_sec)#cbc se commence ici

chif_bloc=CBC_chiffrement(vec_ini, num_sec, ea, x1a, x2a)

#utiliser signature RSA

#sha256 du message
print("voici le hash en nombre décimal ")
Bhachis0=hashlib.sha256(secret.encode(encoding='UTF-8',errors='strict')).digest()
Bhachis1=binascii.b2a_uu(Bhachis0)
Bhachis2=Bhachis1.decode() #en string
Bhachis3=home_string_to_int(Bhachis2)

print("*******************************************************************")
print("On utilise la signature RSA pour obtenir la signature")
print("voici la signature avec la clé privée de Bob")
            
S = CR_Theorem(Bhachis3, db, x1b, x2b)
Cs = CR_Theorem(S, ea, x1a, x2a)
C =  CR_Theorem(Bhachis3, ea, x1a, x2a)

print(S)

print("*******************************************************************")
x=input("appuyer sur entrer")
print("*******************************************************************")
print("*******************************************************************")

print("Alice déchiffre le message chiffré ce qui donne ")
dechif=home_int_to_string(CBC_dechiffrement(vec_ini, chif_bloc, da, x1a, x2a))

print(dechif)
print("*******************************************************************")
print("*******************************************************************")

print("Alice déchiffre la signature de Bob \n", S,"\n ce qui donne  en décimal")

designe = CR_Theorem(Cs, da, x1a, x2a)
print(designe)

if (CR_Theorem(C, da, x1a, x2a) == CR_Theorem(S, eb, x1b, x2b) == Bhachis3):
    print("La signature est valide\n\nTout se passe très bien\nFélicitation!!!")
else:
    print("La signature n'est pas valide")


    
