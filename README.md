/*
Main Ingredients in ectf.
1. getting lambda -> getting inverse of X2 - X1
2. getting Xs into Xs = lamba^2 - X1 - X2

ECTF Setting:
P1 = X1, Y1 in EC SECP256K1
P2 = X2, Y2 in EC SECP256K1

P1 + P2 = (Xs, Ys), where + is group operation.

Output: Alpha, Beta, where Alpha + Beta = Xs

Facts:

Xs = lamba^2 - X1 - X2

lamba = (Y2-Y1)/(X2-X1)

1. GET inverse of X2-X1 
*/

/*
CHECKS:

Alpha1 , Alpha2 = MTA((-X1, R1), (R2,X2))
Where R1 and R2 are points on the EC
1. Alpha1 + Alpha2 = -X1R2 + X2R1

Gamma = (X2-X1)(R1+R2)

Etta1 = R1*GammaInverse 
Etta2 = R2*GammaInverse

2. Etta1 + Etta2 = (X2-X1)inverse

now, 
Beta1, Beta2 = MTA((-Y1, Etta1), (Etta2, Y2))

3. Beta1 + Beta2 = -Y1*Etta2 + Y2*Etta1

now, 
Lamba1 = -Y2*Etta1 + Beta1
Lamba2 = Y2*Etta2 + Beta2

4. Lamba = Lamba1 + Labda2

now, 
use Lambda which is calculated. 
Xs = Lamba^2 - X1 - X2

5. Gamma1, Gamma2 = mta(Lambda1, Lambda2)
Gamma1 + Gamm2 = Lamba1*Lambda2

now, 
S1 = 2Gamma1 + Lambda1^2 - x1
S2 = 2Gamma2 + Lambda2^2 - x2
S = S1 + S2

6. S = Xs = Lambda^2 - X1 - X2
*/

## Fixes

```export LIBRARY_PATH="$LIBRARY_PATH:$(brew --prefix)/lib"```