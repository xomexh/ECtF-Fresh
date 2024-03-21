# ECTF Protocol for MPC-TLS

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

# Current progress

The maths checkout and we have the all the mathmetical checks passing, but the final assertition of Xs = P1 + P2 ( points in EC ) fails most probably due to incorrect parsing of BigInts. Will be verified by once when we get the rustls handshake using ECtF. 

Run using ```cargo run```.

```
[src/main-bkp.rs:222] &x1 = 55066263022277343669578718895168534326250603453777594175500187360389116729240
[src/main-bkp.rs:223] &x2 = 3988119826175064013631855803455705518302985509344127528333651663328583923605
MTA2 Test Satisfied
CHECK 1: Alpha1 + Alpha2 = -X1R2 + X2R1: PASSED
CHECK 1.5: Delta = (X2-X1) * (Rho1 + Rho2): PASSED
CHECK 2: Etta1 + Etta2 = (X2-X1)inverse: PASSED
MTA2 Test Satisfied
CHECK 3: Beta1 + Beta2 = -Y1*Etta2 + Y2*Etta1: PASSED
CHECK 4: Lamba = Lamba1 + Labda2 = (Y2 - Y1) * ((X2-X1)inverse): PASSED
MTA Test MTA1 passed
CHECK5: Gamma1 + Gamm2 = Lamba1*Lambda2 : PASSED
[src/main-bkp.rs:416] &s_sum = 18376196608179464767815969703426572283892154837428299167818235470482919118579
[src/main-bkp.rs:417] &xs_point = 18376196608179464767815969703426572283892154837428299167818235470482919118579
[src/main-bkp.rs:427] &another_s = 18376196608179464767815969703426572283892154837428299167818235470482919118579
CHECK 6: S = Xs = Lambda^2 - X1 - X2 : PASSED
[src/main-bkp.rs:436] &x1 = 55066263022277343669578718895168534326250603453777594175500187360389116729240
[src/main-bkp.rs:437] &x2 = 3988119826175064013631855803455705518302985509344127528333651663328583923605
[src/main-bkp.rs:438] &x1 + &x2 = 59054382848452407683210574698624239844553588963121721703833839023717700652845
[src/main-bkp.rs:439] &x1_x2 = 59054382848452407683210574698624239844553588963121721703833839023717700652845
[src/main-bkp.rs:440] &s_sum = 18376196608179464767815969703426572283892154837428299167818235470482919118579
thread 'main' panicked at 'assertion failed: `(left == right)`
  left: `18376196608179464767815969703426572283892154837428299167818235470482919118579`,
 right: `59054382848452407683210574698624239844553588963121721703833839023717700652845`: ECTF Final Assertion Failed', src/main-bkp.rs:442:5
note: run with `RUST_BACKTRACE=1` environment variable to display a backtrace

```

## Fixes

```export LIBRARY_PATH="$LIBRARY_PATH:$(brew --prefix)/lib"```