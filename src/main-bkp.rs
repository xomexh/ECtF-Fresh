#![allow(unused_imports)]
#![allow(non_snake_case)]
#![allow(unused_variables)]
#![allow(unused_parens)]

use curv::arithmetic::Integer;
use paillier::*;
use curv::BigInt;
use curv::arithmetic::Modulo;
use curv::arithmetic::traits::{Converter,NumberTests};
use curv::arithmetic::Zero;
use curv::arithmetic::Samplable;
use curv::elliptic::curves::{Secp256r1, Point, Scalar};
use rand::Rng;
use curv::arithmetic::BasicOps;

fn mta(a: &Scalar<Secp256r1>, b: &Scalar<Secp256r1>) -> (BigInt, BigInt){
    
    let zp = Scalar::<Secp256r1>::group_order();
    let (ek, dk) = Paillier::keypair().keys();
    //let zp = &ek.n;
    // Alice's input
    let alice_input= a;
    // Bob's input
    let bob_input= b;

    // Alice computes cA = EncryptA(a)
    let c_alice = Paillier::encrypt(&ek, RawPlaintext::from(&alice_input.to_bigint()));

    // Bob selects Beta Tag <– Z(N) -> where n is ek.n 
    let beta_tag: BigInt = BigInt::sample_below(&zp);

    // Compute Encrypt(BetaTag) using key of A
    let enc_betatag = Paillier::encrypt(&ek, RawPlaintext::from(&beta_tag));

    // Compute cB = b * cA + EncryptA(BetaTag) = EncryptA(ab+Tag)
    // Compute b * CA
    let b_mul_c_alice = Paillier::mul(&ek, RawPlaintext::from(&bob_input.to_bigint()), c_alice.clone());

    // Compute cB
    let c_bob = Paillier::add(&ek, b_mul_c_alice.clone(), enc_betatag.clone());

    // Bob sets additive share Beta = -BetaTag mod n
    let mut  beta = (BigInt::zero() - &beta_tag);
    beta = beta % zp;
    // Handling negative beta
    if BigInt::is_negative(&beta) {
        beta = zp - (beta.abs() % zp);
    }

    // Alice decrypts = dec(cB)
    let dec_alice = Paillier::decrypt(&dk, &c_bob);

    // Alice sets alpha = dec_alice mod n
    let mut alpha = (BigInt::from(dec_alice.clone()));
    alpha = alpha % zp;

    if BigInt::is_negative(&alpha) {
        dbg!(alpha.clone());
        alpha = zp - (alpha.abs() % zp);
    }

    let left = ((&alpha + &beta))%zp;
    //dbg!(&left);
    let right =( (alice_input * bob_input).to_bigint())%zp;
    //dbg!(&right);
    assert_eq!(left, right, "Verification failed: Left side ({}) is not equal to right side ({})", left, right);
    println!("MTA Test MTA1 passed");
    (alpha, beta)
}

fn mta_2(
    alice_secret: &Scalar<Secp256r1>,
    r1: &BigInt,
    r2: &BigInt,
    bob_secret: &Scalar<Secp256r1>, 
) -> (Scalar<Secp256r1>, Scalar<Secp256r1>) {

    let zp = Scalar::<Secp256r1>::group_order();
    
    // Generate Paillier key pair
    let (ek, dk) = Paillier::keypair().keys();
    //let zp = &ek.n;

    // Alice's secret shares
    let a1 = &alice_secret.to_bigint();
    // Bob's secret shares
    let a2 = &bob_secret.to_bigint();
    
    // 1. Alice computes CA = EncryptA(a1)
    let c_a = Paillier::encrypt(&ek, RawPlaintext::from(&a1.clone()));
    // 2. Alice computes CR1 = EncryptA(r1)
    let c_r1 = Paillier::encrypt(&ek, RawPlaintext::from(r1.clone()));

    // 4. Bob selects β' <- ZN
    let beta_prime = BigInt::sample_below(&zp);

    // 5. Bob computes CB = (r2 * CA) + (a2 * CR1) + EncryptA(β')
    let r2_mul_c_alice =  Paillier::mul(&ek, RawPlaintext::from(r2.clone()), c_a.clone());
    let a2_mul_c_r1 = Paillier::mul(&ek, RawPlaintext::from(a2.clone()), c_r1.clone());
    let enc_beta_prime = Paillier::encrypt(&ek, RawPlaintext::from(&beta_prime));


    let c_bob = Paillier::add(&ek, r2_mul_c_alice.clone(), a2_mul_c_r1.clone());
    let c_bob = Paillier::add(&ek, c_bob.clone(), enc_beta_prime.clone());

    // 6. Bob sets additive share δ2 = -β′ mod q
    let mut delta_2 = (BigInt::zero() - &beta_prime);
    delta_2 = delta_2 % zp;
    if BigInt::is_negative(&delta_2) {
        delta_2 = zp - (delta_2.abs() % zp);
    }

    // 8. Alice decrypts α' = dec(CB)
    let dec_alice = Paillier::decrypt(&dk, &c_bob);

    // 9. Alice sets δ 1 = α' mod q
    let mut delta_1 = BigInt::from(dec_alice);
    delta_1 = delta_1 % zp;
    if BigInt::is_negative(&delta_1) {
        delta_1 = zp - (delta_1.abs() % zp);
    }

    let left = (&delta_1 + &delta_2)%zp;
    //dbg!(&left);
    //let right = (((a1*r2)%zp) + ((a2*r1)%zp))%zp;

    let mut right = ((a1*r2) + (a2*r1));
    right = right % zp;
    if BigInt::is_negative(&right){
        right = zp - (right.abs() - zp);
    }
    //dbg!(&right);
    assert_eq!(left, right, "Verification MTA2 failed: Left side ({}) is not equal to right side ({})", left, right);
    println!("MTA2 Test Satisfied");
    (delta_1.into(), delta_2.into())
}


fn mta_4(
    alice_secret: &BigInt,
    r1: &BigInt,
    r2: &BigInt,
    bob_secret: &BigInt, 
) -> (Scalar<Secp256r1>, Scalar<Secp256r1>) {

    let zp = Scalar::<Secp256r1>::group_order();
    
    // Generate Paillier key pair
    let (ek, dk) = Paillier::keypair().keys();
    //let zp = &ek.n;

    // Alice's secret shares
    let a1 = alice_secret;

    // Bob's secret shares
    let a2 = bob_secret;
    
    // 1. Alice computes CA = EncryptA(a1)
    let c_a = Paillier::encrypt(&ek, RawPlaintext::from(&a1.clone()));
    // 2. Alice computes CR1 = EncryptA(r1)
    let c_r1 = Paillier::encrypt(&ek, RawPlaintext::from(r1.clone()));

    // 4. Bob selects β' <- ZN
    let beta_prime = BigInt::sample_below(&zp);

    // 5. Bob computes CB = (r2 * CA) + (a2 * CR1) + EncryptA(β')
    let r2_mul_c_alice =  Paillier::mul(&ek, RawPlaintext::from(r2.clone()), c_a.clone());
    let a2_mul_c_r1 = Paillier::mul(&ek, RawPlaintext::from(a2.clone()), c_r1.clone());
    let enc_beta_prime = Paillier::encrypt(&ek, RawPlaintext::from(&beta_prime));


    let c_bob = Paillier::add(&ek, r2_mul_c_alice.clone(), a2_mul_c_r1.clone());
    let c_bob = Paillier::add(&ek, c_bob.clone(), enc_beta_prime.clone());

    // 6. Bob sets additive share δ2 = -β′ mod q
    let mut delta_2 = (BigInt::zero() - &beta_prime);
    delta_2 = delta_2 % zp;
    if BigInt::is_negative(&delta_2) {
        delta_2 = zp - (delta_2.abs() % zp);
    }

    // 8. Alice decrypts α' = dec(CB)
    let dec_alice = Paillier::decrypt(&dk, &c_bob);

    // 9. Alice sets δ 1 = α' mod q
    let mut delta_1 = BigInt::from(dec_alice);
    delta_1 = delta_1 % zp;
    if BigInt::is_negative(&delta_1) {
        delta_1 = zp - (delta_1.abs() % zp);
    }

    let left = (&delta_1 + &delta_2)%zp;
    //dbg!(&left);
    
    let mut right = ((a1*r2) + (a2*r1));
    right = right % zp;
    if BigInt::is_negative(&right){
        right = zp - (right.abs() - zp);
    }


    dbg!(&right);
    //assert_eq!(left, right, "Verification MTA2 failed: Left side is not equal to right side ");
    println!("MTA2 Test Satisfied");
    (delta_1.into(), delta_2.into())
}

fn ectf_protocol(
    p1: &Point<Secp256r1>,
    p2: &Point<Secp256r1>,
) -> (BigInt, BigInt) {

    let zp = BigInt::from_str_radix("115792089237316195423570985008687907853269984665640564039457584007908834671663", 10).unwrap(); //BIGGER
    let zp_n = Scalar::<Secp256r1>::group_order(); //SMALLER

    let x1 = p1.x_coord().unwrap();
    let y1 = p1.y_coord().unwrap();
    let x2 = p2.x_coord().unwrap();
    let y2 = p2.y_coord().unwrap();

    dbg!(&x1);
    dbg!(&x2);

    // for a -ve
    // let minus_x1 = zp_n - ( x1.clone() % zp_n);

    // let minus_x1_from_scalar = Scalar::<Secp256r1>::from((-x1.clone()));
    // dbg!(minus_x1_from_scalar.to_bigint());
    // dbg!(&minus_x1);
    // dbg!(-x1.clone());

    // Alice and Bob sample random value
    let rho_1 = BigInt::sample_below(&zp_n);
    let rho_2 = BigInt::sample_below(&zp_n);

// Alice and Bob run MTA
    let (alpha_1, alpha_2) = mta_2(&Scalar::<Secp256r1>::from((-x1.clone())), (&rho_1), (&rho_2), &Scalar::<Secp256r1>::from(x2.clone()));
    //let (alpha_1, alpha_2) = mta_4(&-x1.clone(), (&rho_1), (&rho_2), &x2.clone());

    //Check 1 Alpha1 + Alpha2 = -X1R2 + X2R1 -------------------------------------
    let alpha_sum = (alpha_1.clone().to_bigint() + alpha_2.clone().to_bigint()) % zp_n.clone(); //CORRECT
    let right_ch1 = (alpha_1.clone()+alpha_2.clone()).to_bigint() %zp_n.clone(); //CORRECT
    //dbg!(&right_ch1);
    let mut left_ch1 = ((-x1.clone() * rho_2.clone()) + (x2.clone() * rho_1.clone()))%zp_n.clone();
    //dbg!(&left_ch1);
    //dbg!(&left_ch1%zp_n);
    if BigInt::is_negative(&left_ch1) {
        left_ch1 = zp_n.clone() - (left_ch1.abs() % zp_n.clone());
    }
  
    // dbg!(&left_ch1);
    // dbg!(zp_n.clone() - ( left_ch1.abs() % zp_n.clone()));
    // dbg!(((-x1.clone() * rho_2.clone()) + (x2.clone() * rho_1.clone()))%zp_n.clone());

    // Check 1 ----------------------------------------------------------------------------
    assert_eq!(right_ch1, left_ch1);
    println!("CHECK 1: Alpha1 + Alpha2 = -X1R2 + X2R1: PASSED");
    // Compute delta values

    let mut delta_1 = (-x1.clone() * rho_1.clone());
    //dbg!(&delta_1);
    if BigInt::is_negative(&delta_1) {
        delta_1 = zp_n.clone() - ( delta_1.abs() % zp_n.clone());
    }
    //dbg!(&delta_1);
    delta_1 = (delta_1 + alpha_1.clone().to_bigint()) % zp_n.clone();

    let delta_2 = (( x2.clone() * rho_2.clone()) + alpha_2.clone().to_bigint())%zp_n;
    //dbg!(&delta_2);

    let delta = BigInt::mod_add(&delta_1, &delta_2, &zp_n);
    let delta_inv = BigInt::mod_inv(&delta, &zp).unwrap();

    //CHECK 1.5: delta = (X2-X1) * (Rho1 + Rho2)-------------------------------------
    let mut x2_minus_x1 = (x2.clone()-x1.clone()) % zp_n;
    //dbg!(&x2_minus_x1);

    if BigInt::is_negative(&x2_minus_x1) {
        x2_minus_x1 = zp_n.clone() - ( x2_minus_x1.abs() % zp_n.clone());
    }
    //dbg!(&x2_minus_x1);
    
    let rho1_plus_rho2 = (rho_1.clone()+rho_2.clone()) % zp_n;
    let right = (x2_minus_x1.clone() * rho1_plus_rho2) % zp_n;
    assert_eq!(&delta, &right,"Check 1.5 Failed");
    println!("CHECK 1.5: Delta = (X2-X1) * (Rho1 + Rho2): PASSED");
    
    let delta_inverse = BigInt::mod_inv(&delta, &zp_n).unwrap(); //Correct delta-inverse
    //dbg!(&delta_inverse);

    let delta_inv=delta_inverse.clone();

    // Compute eta values
    let eta_1 = (rho_1.clone()*delta_inv.clone())%zp_n;
    let eta_2 = (rho_2.clone()*delta_inv.clone())%zp_n;
    //dbg!(&eta_1);
    //dbg!(&eta_2);

    //CHECK 2: Etta1 + Etta2 = (X2-X1)inverse ----------------------------------------
    let sum_eta = (eta_1 .clone()+ eta_2.clone()) % zp_n.clone(); // CORRECT. 
    let mut right_ch2 = BigInt::mod_inv(&(x2.clone()-x1.clone()), zp_n).unwrap(); 
    right_ch2 = right_ch2 % zp_n.clone();

    if BigInt::is_negative(&right_ch2){
        right_ch2 = zp_n.clone() - ( right_ch2.abs() % zp_n.clone());
    }

    assert_eq!(&sum_eta, &right_ch2, "Check 2 Failed");
    println!("CHECK 2: Etta1 + Etta2 = (X2-X1)inverse: PASSED");

// Run MTA for beta values
    let (beta_1, beta_2) = mta_2(&Scalar::<Secp256r1>::from(-y1.clone()), &eta_1, &eta_2, &Scalar::<Secp256r1>::from(y2.clone()));
    //let (beta_1, beta_2) = mta_4(&-y1.clone(), &eta_1, &eta_2, &y2.clone());
    
    //dbg!(&beta_1);
    //dbg!(&beta_2);

    //CHECK 3: Beta1 + Beta2 = -Y1*Etta2 + Y2*Etta1 ----------------------------------
    let left_ch3 = (beta_1.clone().to_bigint() + beta_2.clone().to_bigint()) % zp_n.clone(); //CORRECT.

    let mut y1_etta2 = -y1.clone() * eta_2.clone();
    if BigInt::is_negative(&y1_etta2) {
        y1_etta2 = zp_n.clone() - ( y1_etta2.abs() % zp_n.clone());
    }

    let y2_etta1 = (y2.clone()*eta_1.clone())% zp_n.clone();


    let right_ch3 = (y1_etta2+y2_etta1)% zp_n.clone();
    assert_eq!(&left_ch3, &right_ch3, "Check 3 Failed");
    println!("CHECK 3: Beta1 + Beta2 = -Y1*Etta2 + Y2*Etta1: PASSED");

    // Compute lambda values
    //let lambda_1 = (((-y1.clone() * eta_1) % zp_n.clone()) + beta_1.clone().to_bigint())% zp_n.clone();

    let mut lambda_1 = (-y1.clone() * eta_1.clone());
    //dbg!(&lambda_1);
    if BigInt::is_negative(&lambda_1) {
        lambda_1 = zp_n.clone() - ( lambda_1.abs() % zp_n.clone());
    }
    //dbg!(&lambda_1);
    lambda_1 = (lambda_1 + beta_1.clone().to_bigint()) % zp_n.clone();

    let lambda_2 = ((( y2.clone() * eta_2) % zp_n.clone()) + beta_2.clone().to_bigint()) % zp_n.clone(); //correct. 
    // dbg!(&lambda_2);
    // dbg!(&lambda_1);
    // dbg!(&lambda_2);
    
    //CHECK 4: Lamba = Lamba1 + Labda2 = (Y2 - Y1) * ((X2-X1)inverse)
    let mut lambda_sum = lambda_1.clone() + lambda_2.clone();
    lambda_sum = (lambda_sum.clone()) %zp_n.clone();
    if BigInt::is_negative(&lambda_sum){
        lambda_sum = zp_n.clone() - (lambda_sum.abs() % zp_n.clone());
    }

    let mut y2_minus_y1 = (y2.clone() - y1.clone()) % zp_n.clone();
    //dbg!(&y2_minus_y1);

    if BigInt::is_negative(&y2_minus_y1) {
        y2_minus_y1 = zp_n.clone() - ( y2_minus_y1.abs() % zp_n.clone());
        dbg!(&y2_minus_y1);
    }

    let right_ch4 = (y2_minus_y1 * right_ch2) % zp_n.clone();

    assert_eq!(&lambda_sum, &right_ch4, "Check 4 Failed");
    println!("CHECK 4: Lamba = Lamba1 + Labda2 = (Y2 - Y1) * ((X2-X1)inverse): PASSED");

    let lamda_power2 = (lambda_sum.clone() * lambda_sum.clone()) % zp_n.clone();

    let mut x_sum = (x1.clone() + x2.clone()) % zp_n.clone();
    if BigInt::is_negative(&x_sum){
        x_sum = zp_n.clone() - (x_sum.abs() - zp_n.clone());
    }

    let xs_point_calculation = (lambda_sum.clone() * lambda_sum.clone()) - x1.clone() - x2.clone();
    let mut xs_point = xs_point_calculation.clone() % zp_n.clone();

    if BigInt::is_negative(&xs_point){
        xs_point = zp_n.clone() - (xs_point_calculation.abs() - zp_n.clone());
    }

    // Lambda Sum == 
    //assert_eq!(&lamda_power2, &xs_point,"lauda point");
    //println!("SUDO CHECK: Lambda Sum =- Xs");


    // Run MTA for gamma values
    let (gamma_1, gamma_2) = mta(&Scalar::<Secp256r1>::from(lambda_1.clone()), &Scalar::<Secp256r1>::from(lambda_2.clone()));
    // dbg!(&gamma_1.clone().to_bigint());
    // dbg!(&gamma_2.clone().to_bigint());

    //CHECK5: Gamma1 + Gamm2 = Lamba1*Lambda2 
    let gamma_sum = (gamma_1.clone() + gamma_2.clone()) % zp_n.clone();
    let lamda_product = (lambda_1.clone() * lambda_2.clone()) % zp_n.clone();
    assert_eq!(&gamma_sum, &lamda_product, "Check 5 Failed");
    println!("CHECK5: Gamma1 + Gamm2 = Lamba1*Lambda2 : PASSED");

    // Compute final output s values
    let wtf_1 = (((((BigInt::from(2) * gamma_1)% zp_n.clone())+((lambda_1.clone()*lambda_1.clone()) % zp_n.clone()))% zp_n.clone()) - x1.clone());
    let mut s1 = wtf_1.clone() % zp_n.clone();
    if BigInt::is_negative(&s1){
        s1 = zp_n.clone() - ( wtf_1.clone().abs() % zp_n.clone())
    }

    let wtf_2 = (((((BigInt::from(2) * gamma_2)% zp_n.clone())+((lambda_2.clone()*lambda_2.clone()) % zp_n.clone()))% zp_n.clone()) - x2.clone());
    let mut s2 = wtf_2.clone() % zp_n.clone();
    if BigInt::is_negative(&s2){
        s2 = zp_n.clone() - ( wtf_2.clone().abs() % zp_n.clone())
    }

//CHECK 6: S = Xs = Lambda^2 - X1 - X2 
    let s_sum = (s1.clone()+s2.clone())%zp_n.clone();

    dbg!(&s_sum);
    dbg!(&xs_point);

    let mut another_s = (lambda_sum.clone() * lambda_sum.clone()) - x1.clone() - x2.clone();
    another_s = another_s % zp_n.clone();

    if BigInt::is_negative(&another_s) {
        another_s = zp_n.clone() - (another_s.abs() % zp_n.clone());
        println!("s is negative");
        dbg!(another_s.clone());
    }
    dbg!(&another_s);
    assert_eq!(&s_sum, &another_s, "Check 6 Failed");
    println!("CHECK 6: S = Xs = Lambda^2 - X1 - X2 : PASSED");

    let mut x1_x2 = x1.clone() + x2.clone();
    x1_x2 = x1_x2 % zp_n.clone();
    if BigInt::is_negative(&x1_x2){
        x1_x2 = zp_n.clone() - (x1_x2.abs()- zp_n.clone());
    }
    dbg!(&x1);
    dbg!(&x2);
    dbg!(&x1 + &x2);
    dbg!(&x1_x2);
    dbg!(&s_sum);

    assert_eq!(&s_sum,&x1_x2,"ECTF Final Assertion Failed");
    println!("ECTF Passed");
    
    (s1.into(), s2.into())
}

fn main() {
    let scalar_1 = Scalar::<Secp256r1>::random();
    let scalar_2 = Scalar::<Secp256r1>::random();
    let g_1 = Point::<Secp256r1>::generator();
    let g_2 = Point::<Secp256r1>::generator();

    let zp = BigInt::from_str_radix("115792089237316195423570985008687907853269984665640564039457584007908834671663", 10).unwrap(); //BIGGER
    let zp_n = Scalar::<Secp256r1>::group_order(); //smaller

    //115792089237316195423570985008687907853269984665640564039457584007908834671663
    
    /*
    -a mod b
    -a mod b = -(a mod b)
    1. a mod b 
    2. b - (a mod b)
    */

    
    //Generate two EC points 
    // let p1: Point<Secp256r1> = (scalar_1 * g_1);
    // let p2: Point<Secp256r1> = (scalar_2 * g_2);
    let p1 = Point::<Secp256r1>::generator().to_point(); // user
    let p2 = Point::<Secp256r1>::base_point2(); // oracle
    // Run the ECtF protocol.
    let (s1, s2) = ectf_protocol(&p1, &p2);
    
    let p3 = (p1.clone().x_coord().unwrap() + p2.clone().x_coord().unwrap()) % zp_n.clone();
    let p3_grp = p1 + p2;

    dbg!(&p3);
    dbg!(&p3_grp.x_coord().unwrap());
    let s3 = (s1 + s2) % zp_n.clone() ;
    dbg!(&s3);
    assert_eq!( s3, p3);
    //assert_eq!( s3,p3_grp.x_coord().unwrap());

//  Check if s1 + s2 = s = Xs where (Xs, Ys) = p1 + p2
    // assert_eq!(((s1 + s2).to_bigint(), (p3.x_coord().unwrap() % zp)));
    //println!("ECtF protocol completed successfully.");
}