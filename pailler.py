"""
Implémentation du cryptosystème de Paillier
DM Cryptographie - M1 Informatique, Université de Lorraine 2025/2026
Auteurs : Cissé Papa El Hadji G, Keita Mahamadou & Abogounrin Ayath
"""

import secrets
import sympy
import sys

# Q4 - Exponentiation modulaire binaire

def exp_mod_recursive(g, a, n):
    if a == 0:
        return 1
    elif a == 1:
        return g % n
    elif a % 2 == 0:  # a pair
        return  exp_mod_recursive((g*g) % n, a//2, n)
    else: # a > 2 impair
        print(f"a = {a}")
        return (g * exp_mod_recursive((g*g) % n, (a-1)//2, n)) % n

def ExpMod(c, a, N):

    if a == 0:
        return 1

    res = 1
    base = c % N

    while a > 0:
        if a % 2 == 1:  # bit courant = 1
            res = (res * base) % N
        base = (base * base) % N
        a = a // 2

    return res

# Q5 - Génération des clefs

def generer_grand_nombre_premier(bits=1024):
    while True:
        nombre_aleotoire = secrets.randbits(bits)

        decal_binaire = 1 << (bits - 1)   # un nombre avec uniquement le bit de poids fort à 1
        nombre_aleotoire |= decal_binaire   # force le bit de poids fort à 1 avec un OU binaire afin d'avoir un nombre de 1024 bits

        if sympy.isprime(nombre_aleotoire):
            return nombre_aleotoire

def KeyGen(bits=1024):
    p = generer_grand_nombre_premier(bits)
    q = generer_grand_nombre_premier(bits)

    while q == p:
        q = generer_grand_nombre_premier(bits)
    N = p * q
    phi_N = (p -1) * (q - 1)

    return N, phi_N

#Q6 - Chiffrement et déchiffrement
def Enc(m,N):
    r = secrets.randbits(2048) #r doit être  inférieur à N, N est de 2048 bits(p et q sont de 1024 bits)
    while r <= 0 or r >= N: 
        r=secrets.randbits(2048)
    c = (ExpMod(1 + N, m, N**2) * ExpMod(r, N, N**2)) % (N**2)

    return c, r



def euclide_etendu(a, b):
    #a*u + b*v = PGCD(a, b)
    #j'utilise la formule vue en cours
    changement = False
    if a < b:
        changement = True
        temp = a
        a = b
        b = temp

    u0, u1 = 1, 0
    v0, v1 = 0, 1
    u , v = 0, 0
    while b != 0:
        q = a // b
        r = a % b
        a, b = b, r
        u = u0 - q * u1
        v = v0 - q * v1

        #je remplie u0 et u1 avec les valeurs actuelles et pareille pour v0 et v1
        u0, u1 = u1, u
        v0, v1 = v1, v

    if changement:
        return a, v0, u0

    return a, u0, v0

def inverse_mod(a, n):
    #Retourne a**(-1) mod n via Euclide étendu
    Pgcd, u, v = euclide_etendu(a, n)
    if Pgcd != 1:
        raise ValueError(f"{a} n'est pas inversible mod {n}")
    return u % n

def Dec(c, N, phi_N):
    exp_r = inverse_mod(N, phi_N)
    r = ExpMod(c, exp_r, N)
    #r = ExpMod(c,ExpMod(N, -1, phi_N), N)

    r_inv = inverse_mod(r, N**2)
    r_invN = ExpMod(r_inv, N, N ** 2)
    m = ((c * r_invN ) % N**2 - 1) // N

    return m
# Main

def main():
    sorties = []

    def log(s=""):
        print(s)
        sorties.append(s)


    # Génération des clefs (couteux, on le fait une fois)

    log("=" * 70)
    log("Génération des clefs (1024 bits)")
    log("=" * 70)

    N, phi_N = KeyGen(bits=1024)

    log(f"pk = N       = {N}")
    log(f"sk = phi(N)  = {phi_N}")
    log()

    # Q4 - Test ExpMod sur 10 grands nombres
    log("=" * 70)
    log("Q4 - Test ExpMod() sur 10 grands nombres")
    log("=" * 70)
    for i in range(1, 11):

        base = secrets.randbits(256)
        exp = secrets.randbits(256)
        mod = secrets.randbits(256)

        # Résultat de notre implémentation
        res_expMod = ExpMod(base, exp, mod)

        # Résultat Python (pow à 3 arguments)
        res_pow3 = pow(base, exp, mod)

        match = "OK" if res_expMod == res_pow3 else "ERREUR"

        log(f"Test {i}: base({base.bit_length()} bits) ^ exp({exp.bit_length()} bits)"f" mod mod({mod.bit_length()} bits)")
        log(f"  Notre ExpMod  = {res_expMod}")
        log(f"  pow() Python  = {res_pow3}")
        log(f"  Résultat      : {match}")
        log()

    # Q5 - Les clefs ont déjà été effectuées, on vérifie juste la taille

    log("="*70)
    log("Q5 - Vérification KeyGen()")
    log("="*70)
    log(f"Taille de N      : {N.bit_length()} bits (attendu ≥ 2048)")
    log(f"Taille de phi(N) : {phi_N.bit_length()} bits")
    log()

    x = 17
    n = 3120
    inv = inverse_mod(x, n)
    log(f"Test inverse_mod: 17^-1 mod 3120 = {inv}, vérif: {(x * inv) % n} (attendu 1)")
    # Q6 - Test chiffrement et déchiffrement
    log("="*70)
    log("Q6 - Test chiffrement/déchiffrement")
    log("="*70)
    for i in range(1,101):
        m = secrets.randbits(2048)
        while m < 0 or m >= N:
            m = secrets.randbits(2048)
        c, r = Enc(m, N)
        m_dechiffre = Dec(c, N, phi_N)

        if m == m_dechiffre:
            match = "OK" 
        else:
            match = "ERREUR"

        log(f"Test {i}:")
        log(f"  Message original : {m}")
        log(f"  Chiffrement     : {c} (r={r})")
        log(f"  Déchiffrement   : {m_dechiffre}")   
        log(f"  Résultat        : {match}")
        log()

if __name__ == "__main__":
    main()