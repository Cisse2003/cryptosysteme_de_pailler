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

    if a == 1:
        return g % n
    elif a % 2 == 0:  # a pair
        return  exp_mod_recursive((g*g) % n, a//2, n)
    else: # a > 2 impair
        return (g * exp_mod_recursive((g*g) % n, (a-1)//2, n)) % n

def ExpMod(c, a, N):
    if a == 0:
        return 1 % N
    return exp_mod_recursive(c, a, N)

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

if __name__ == "__main__":
    main()