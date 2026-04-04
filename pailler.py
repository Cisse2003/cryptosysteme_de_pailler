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





# Main

def main():
    sorties = []

    def log(s=""):
        print(s)
        sorties.append(s)


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

if __name__ == "__main__":
    main()