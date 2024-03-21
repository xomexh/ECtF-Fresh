#![allow(unused_imports)]
#![allow(non_snake_case)]
#![allow(unused_variables)]
#![allow(unused_parens)]
#![allow(dead_code)]

use curv::arithmetic::Integer;
use curv::arithmetic::NumberTests;
use paillier::*;
use curv::BigInt;
use curv::arithmetic::BasicOps;
use curv::arithmetic::Modulo;
use curv::arithmetic::traits::Converter;
use curv::arithmetic::Zero;
use curv::arithmetic::Samplable;
use curv::elliptic::curves::{secp256_k1::Secp256k1, Point, Scalar};
use rand::Rng;

fn mta_1(a: &Scalar<Secp256k1>, b: &Scalar<Secp256k1>) -> (BigInt, BigInt){
    let zp = BigInt::from_str_radix("115792089237316195423570985008687907853269984665640564039457584007908834671663", 10).unwrap();
    let order = Scalar::<Secp256k1>::group_order();

    // Pailier keys
    let (ek, dk) = Paillier::keypair().keys();
    
    // Alice input
    let alice_input=a;
    let bob_input=b;

   // Alice computes cA = EncryptA(a)
   let c_alice = Paillier::encrypt(&ek, RawPlaintext::from(&alice_input.to_bigint()));
    
    // beta_tag
    let beta_tag: BigInt = BigInt::sample_below(&ek.n);

    // Compute Encrypt(BetaTag) using key of A
    let enc_betatag = Paillier::encrypt(&ek, RawPlaintext::from(&beta_tag));

    let b_mul_c_alice = Paillier::mul(&ek, RawPlaintext::from(&bob_input.to_bigint()), c_alice.clone());
    let c_bob = Paillier::add(&ek, b_mul_c_alice.clone(), enc_betatag.clone());

    let mut  beta = BigInt::zero() - &beta_tag;

    // Handling negative beta
    if BigInt::is_negative(&beta) {
        beta = order - (beta.abs() % order);
        dbg!(beta.clone());
    }
    else 
    {
        beta = beta % order;
        dbg!(beta.clone());

    }

    // Alice decrypts = dec(cB)
    let dec_alice = Paillier::decrypt(&dk, &c_bob);
    let mut alpha = (BigInt::from(dec_alice.clone()));
    alpha = alpha % order;

    if BigInt::is_negative(&alpha) {
        dbg!(alpha.clone());
        alpha = order - (alpha.abs() % order);
    }

    (alpha, beta)
}

fn mta_2(
    alice_secret: &Scalar<Secp256k1>,
    r1: &BigInt,
    r2: &BigInt,
    bob_secret: &Scalar<Secp256k1>,
)-> (BigInt, BigInt){

    let zp = BigInt::from_str_radix("115792089237316195423570985008687907853269984665640564039457584007908834671663", 10).unwrap();

    let order = Scalar::<Secp256k1>::group_order();

    // Generate Paillier key pair
    let (ek, dk) = Paillier::keypair().keys();

    // Alice's secret shares
    let a1 = &alice_secret.to_bigint();
    // Bob's secret shares
    let a2 = &bob_secret.to_bigint();

    // 1. Alice computes CA = EncryptA(a1)
    let c_a = Paillier::encrypt(&ek, RawPlaintext::from(&a1.clone()));
    // 2. Alice computes CR1 = EncryptA(r1)
    let c_r1 = Paillier::encrypt(&ek, RawPlaintext::from(r1.clone()));

    // 4. Bob selects β' <- ZN
    let beta_prime = BigInt::sample_below(&ek.n);

    // 5. Bob computes CB = (r2 * CA) + (a2 * CR1) + EncryptA(β')
    let r2_mul_c_alice =  Paillier::mul(&ek, RawPlaintext::from(r2.clone()), c_a.clone());
    let a2_mul_c_r1 = Paillier::mul(&ek, RawPlaintext::from(a2.clone()), c_r1.clone());
    let enc_beta_prime = Paillier::encrypt(&ek, RawPlaintext::from(&beta_prime));

    let c_bob = Paillier::add(&ek, r2_mul_c_alice.clone(), a2_mul_c_r1.clone());
    let c_bob = Paillier::add(&ek, c_bob.clone(), enc_beta_prime.clone());

    let mut delta_2 = (BigInt::zero() - &beta_prime) ;

    delta_2 = delta_2 % order;

    if BigInt::is_negative(&delta_2) {
        
        delta_2 = order - (delta_2.abs() % order);
        dbg!(delta_2.clone());
    }

     // 8. Alice decrypts α' = dec(CB)
     let dec_alice = Paillier::decrypt(&dk, &c_bob);

    // 9. Alice sets δ 1 = α' mod q
    let mut delta_1 = BigInt::from(dec_alice);
    delta_1 = delta_1 % order;

    if BigInt::is_negative(&delta_1) {
        delta_1 = order - (delta_1.abs() % order);
        dbg!(delta_1.clone());
    }
       
    //(delta_1.into(), delta_2.into())
    (delta_1, delta_2)
}




fn main() {
    let scalar_1 = Scalar::<Secp256k1>::random();
    let scalar_2 = Scalar::<Secp256k1>::random();
    let g_1 = Point::<Secp256k1>::generator();
    let g_2 = Point::<Secp256k1>::generator();
// mod p
    let zp = BigInt::from_str_radix("115792089237316195423570985008687907853269984665640564039457584007908834671663", 10).unwrap();
    let order = Scalar::<Secp256k1>::group_order();

    // let p1: Point<Secp256k1> = scalar_1 * g_1;
    // let p2: Point<Secp256k1> = scalar_2 * g_1;

    let p1 = Point::<Secp256k1>::generator().to_point(); // user
    let p2 = Point::<Secp256k1>::base_point2(); // oracle


    let x1 = p1.x_coord().unwrap();
    let y1 = p1.y_coord().unwrap();
    let x2 = p2.x_coord().unwrap();
    let y2 = p2.y_coord().unwrap();

    // println!("\n Checking Mta1.... \n");

    // let (alpha, beta) = mta_1(&Scalar::<Secp256k1>::from(x1.clone()), &Scalar::<Secp256k1>::from(y1.clone()));
    
    // let mut mul_check = (x1.clone() * y1.clone() ) % order;
    

    // if BigInt::is_negative(&mul_check) {
    //     dbg!(mul_check.clone());
    //     mul_check = order - (mul_check.abs() % order);
    // }
    // else 
    // {
    //     mul_check = mul_check % order;
    //     dbg!(mul_check.clone());

    // }

    // let mut sum_ = (alpha + beta ) % order;

    // if BigInt::is_negative(&sum_) {
    //     dbg!(sum_.clone());
    //     sum_ = order - (sum_.abs() % order);
    // }
    // else 
    // {
    //     sum_ = sum_ % order;
    //     dbg!(sum_.clone());

    // }


    // assert_eq!(sum_.clone() , mul_check.clone() , "Mta1Check failed");
    // println!("Mta1 check successful!!");

    // println!("\n Checking Mta2....");

    // let rho_1 = BigInt::sample_below(order);
    // dbg!(&rho_1); 
    // let rho_2 = BigInt::sample_below(order);
    // dbg!(&rho_2);

    // let (alpha_1, alpha_2) = mta_2(&Scalar::<Secp256k1>::from(-x1.clone()), &rho_1, &rho_2, &Scalar::<Secp256k1>::from(x2.clone()) );

    // let mut  sum = alpha_1 + alpha_2;
    // if BigInt::is_negative(&sum) {
    //     dbg!(sum.clone());
    //     sum = order - (sum.abs() % order);
    // }
    // else 
    // {
    //     sum = sum % order;
    //     dbg!(sum.clone());

    // }

    
    let (s1, s2) = ectf_protocol(&p1, &p2);

    let mut s = s1.clone() + s2.clone();
    s = s % order;

    if BigInt::is_negative(&s) {
        s = order - (s.abs() % order);
        dbg!(s.clone());
    }
    else 
    {
        s = s % order;
        dbg!(s.clone());

    }

    let mut  x = x1.clone() + x2.clone();
    x = x % order;

    if BigInt::is_negative(&x) {
        x = order - (x.abs() % order);
        println!("x is negative");
        dbg!(x.clone());
    }
    else 
    {
        x = x % order;
        dbg!(x.clone());
    }

    assert_eq!(s, x, "ECTF Failed");
    println!("ECTF Successful");
}

fn ectf_protocol(
    p1: &Point<Secp256k1>,
    p2: &Point<Secp256k1>,
)->(BigInt, BigInt){

    let x1 = p1.x_coord().unwrap();
    let y1 = p1.y_coord().unwrap();
    let x2 = p2.x_coord().unwrap();
    let y2 = p2.y_coord().unwrap();

    let zp = BigInt::from_str_radix("115792089237316195423570985008687907853269984665640564039457584007908834671663", 10).unwrap();

    let order = Scalar::<Secp256k1>::group_order();

    let rho_1 = BigInt::sample_below(order);
    dbg!(&rho_1); 
    let rho_2 = BigInt::sample_below(order);
    dbg!(&rho_2);

    //1. Alice and Bob run MTA
    let (alpha_1, alpha_2) = mta_2(&Scalar::<Secp256k1>::from(-x1.clone()), &rho_1, &rho_2, &Scalar::<Secp256k1>::from(x2.clone()) );

    let mut  sum = alpha_1.clone() + alpha_2.clone();
    if BigInt::is_negative(&sum) {
        dbg!(sum.clone());
        sum = order - (sum.abs() % order);
    }
    else 
    {
        sum = sum % order;
        dbg!(sum.clone());

    }

    let  mul_x1= (-(x1.clone())) * rho_2.clone();
    let  mul_x2= x2.clone() * rho_1.clone();

    let mut x1x2 = mul_x1.clone() + mul_x2.clone();

    x1x2 = x1x2 % order;

    if BigInt::is_negative(&x1x2) {
        x1x2 = order - (x1x2.abs() % order);
        dbg!(x1x2.clone());
    }
    else 
    {
        x1x2 = x1x2 % order;
        dbg!(x1x2.clone());

    }

    assert_eq!(sum, x1x2, "Mta 2 Check 1 Failed");
    dbg!(&alpha_1.clone());
    dbg!(&alpha_2.clone());
    println!("Mta 2 Check 1 passed");

    // Compute delta values
    println!(" Compute Delta1 and Delta2....");
    let mut delta_1 = (-x1.clone() * rho_1.clone()) + alpha_1.clone();
    delta_1 = delta_1 % order;
    println!("Check negative delta1 and adjust with modulus order ");
    if BigInt::is_negative(&delta_1) {
        delta_1 = order - (delta_1.abs() % order);
        dbg!(delta_1.clone());
    }
    else 
    {
        delta_1 = delta_1 % order;
        dbg!(delta_1.clone());

    }

    let mut delta_2 = (x2.clone() * rho_2.clone() )+ alpha_2.clone();
    
    delta_2 = delta_2 % order;

    if BigInt::is_negative(&delta_2) {
        delta_2 = order - (delta_2.abs() % order);
        dbg!(delta_2.clone());
    }
    else 
    {
        delta_2 = delta_2 % order;
        dbg!(delta_2.clone());

    }

    dbg!(delta_1.clone());
    dbg!(delta_2.clone());

    println!("Compute delta");

    let mut delta = delta_1.clone()+ delta_2.clone();
    delta = delta % order;

    if BigInt::is_negative(&delta) {
        delta = order - (delta.abs() % order);
        dbg!(delta.clone());
    }
    else 
    {
        delta = delta % order;
        dbg!(delta.clone());

    }

    println!("compute Delta-inv");

    // let gcd = delta.gcd(&zp); 
    // if gcd != BigInt::from(1) {
    //      panic!("GCD of delta and zp is not 1, modular inverse does not exist.");
    //  }
    // else{
    //     println!("Successful GCD");
    // }

    let mut delta_inv=BigInt::mod_inv(&delta, order).unwrap();
    dbg!(&delta_inv.clone());

    delta_inv = delta_inv % order;

    if BigInt::is_negative(&delta_inv) {
        delta_inv = order - (delta_inv.abs() % order);
        dbg!(delta_inv.clone());
        println!("Delta inv is negative")
    }
    else 
    {
        delta_inv = delta_inv % order;
        dbg!(delta_inv.clone());

    }


    println!("successfully computed delta inv");

    // Compute eta values
    let eta_1=rho_1*delta_inv.clone();
    let eta_2=rho_2*delta_inv.clone();

    let mut e1e2 = eta_1.clone() + eta_2.clone();
    e1e2 = e1e2 % order;

    if BigInt::is_negative(&e1e2) {
        e1e2 = order - (e1e2.abs() % order);
        println!("e1e2 is negative");
        dbg!(e1e2.clone());
    }
    else 
    {
        e1e2 = e1e2 % order;
        dbg!(e1e2.clone());

    }

    let mut x2_x1 = BigInt::mod_inv(&(x2.clone() - x1.clone()), order).unwrap() ;
    x2_x1=x2_x1 % order;

    if BigInt::is_negative(&x2_x1) {
        x2_x1 = order - (x2_x1.abs() % order);
        println!("x2_x1 is negative");
        dbg!(x2_x1.clone());
    }
    else 
    {
        x2_x1 = x2_x1 % order;
        dbg!(x2_x1.clone());

    }

    assert_eq!(e1e2.clone(), x2_x1.clone(), "Slope check failed");
    println!("x2 - x1 check successful!");

    // Run MTA for beta values

    println!("Mta2 Check Started.....");
    let  (beta_1, beta_2) = mta_2(&Scalar::<Secp256k1>::from(-y1.clone()), &eta_1, &eta_2, &Scalar::<Secp256k1>::from(y2.clone()));
    dbg!(&beta_1);
    dbg!(&beta_2);

    let mut beta_sum = beta_1.clone() + beta_2.clone();
    beta_sum = beta_sum % order;

    if BigInt::is_negative(&beta_sum) {
        beta_sum = order - (beta_sum.abs() % order);
        println!("beta sum is negative");
        dbg!(beta_sum.clone());
    }
    else 
    {
        beta_sum = beta_sum % order;
        dbg!(beta_sum.clone());

    }

    let mut check_beta = (-(y1.clone()) * eta_2.clone()) + (y2.clone() * eta_1.clone());
    check_beta = check_beta % order;

    if BigInt::is_negative(&check_beta) {
        check_beta = order - (check_beta.abs() % order);
        println!("beta sum is negative");
        dbg!(check_beta.clone());
    }
    else 
    {
        check_beta= check_beta % order;
        dbg!(check_beta.clone());

    }

    assert_eq!(beta_sum, check_beta, " beta check failed");
    println!("Beta check successful");

    println!("lambda 1 and lambda 2 computation ...");

    let mut lambda_1 = (-y1.clone() * eta_1) + beta_1.clone();
    lambda_1 = lambda_1 % order;


    if BigInt::is_negative(&lambda_1) {
        lambda_1 = order - (lambda_1.abs() % order);
        println!("lambda1 sum is negative");
        dbg!(lambda_1.clone());
    }
    else 
    {
        lambda_1= lambda_1 % order;
        dbg!(lambda_1.clone());

    }

    let mut lambda_2 = (y2.clone() * eta_2 )+ beta_2.clone();
    lambda_2 = lambda_2 % order;


    if BigInt::is_negative(&lambda_2) {
        lambda_2 = order - (lambda_2.abs() % order);
        println!("lambda2 is negative");
        dbg!(lambda_2.clone());
    }
    else 
    {
        lambda_2= lambda_2 % order;
        dbg!(lambda_2.clone());

    }

    dbg!(&lambda_1);
    dbg!(&lambda_2);

    println!("lambda calculation");
    let mut lambda = lambda_1.clone() + lambda_2.clone();
    lambda=lambda%order;

    if BigInt::is_negative(&lambda) {
        lambda = order - (lambda.abs() % order);
        println!("lambda is negative");
        dbg!(lambda.clone());
    }
    else 
    {
        lambda= lambda % order;
        dbg!(lambda.clone());

    }

    let mut slope = (y2.clone()-y1.clone())*x2_x1;
    slope=slope % order;

    if BigInt::is_negative(&slope) {
        slope = order - (slope.abs() % order);
        println!("slope is negative");
        dbg!(slope.clone());
    }
    else 
    {
        slope= slope % order;
        dbg!(slope.clone());

    }

    assert_eq!(lambda, slope, "SLOPE CHECK FAILED");
    println!("SLOPE CHECK SUCCESSFUL");

    println!("Compute Gamma1 and Gamma2 with MTA1");

    let (gamma_1, gamma_2) =  mta_1(&Scalar::<Secp256k1>::from(lambda_1.clone()), &Scalar::<Secp256k1>::from(lambda_2.clone()));

    let mut sum_g=gamma_1.clone() + gamma_2.clone();
    sum_g = sum_g % order;

    if BigInt::is_negative(&sum_g) {
        sum_g = order - (sum_g.abs() % order);
        println!("sum_g is negative");
        dbg!(sum_g.clone());
    }
    else 
    {
        sum_g= sum_g % order;
        dbg!(sum_g.clone());

    }

    let mut mul_l = lambda_1.clone() * lambda_2.clone();
    mul_l = mul_l % order;

    if BigInt::is_negative(&mul_l) {
        mul_l = order - (mul_l.abs() % order);
        println!("mul_l is negative");
        dbg!(mul_l.clone());
    }
    else 
    {
        mul_l= mul_l % order;
        dbg!(mul_l.clone());

    }

    assert_eq!(mul_l, sum_g, "lambda and mul_l failed");
    println!("Lambda and mul_l is successful");

     // Compute final output s values

     let mut s1 = ((BigInt::from(2) * gamma_1) +( (lambda_1.clone()*lambda_1.clone()) - x1.clone()));

     s1 = s1 % order;

     if BigInt::is_negative(&s1) {
        s1 = order - (s1.abs() % order);
        println!("s1 is negative");
        dbg!(s1.clone());
    }
    else 
    {
        s1= s1 % order;
        dbg!(s1.clone());

    }

    let mut s2 = ((BigInt::from(2) * gamma_2) + ((lambda_2.clone()*lambda_2.clone()) - x2.clone()));
    s2=s2 % order;

    if BigInt::is_negative(&s2) {
        s2 = order - (s2.abs() % order);
        println!("s2 is negative");
        dbg!(s2.clone());
    }
    else 
    {
        s2= s2 % order;
        dbg!(s2.clone());

    }

   let mut sum_s = s1.clone() + s2.clone();
   sum_s = sum_s % order;

   if BigInt::is_negative(&sum_s) {
    sum_s = order - (sum_s.abs() % order);
    println!("sum_s is negative");
    dbg!(sum_s.clone());
    }
    else 
    {
        sum_s= sum_s % order;
        dbg!(sum_s.clone());
    }

    let mut xx21 = BigInt::mod_inv(&(x2.clone() - x1.clone()), order).unwrap() ;
    xx21=xx21 % order;

    if BigInt::is_negative(&xx21) {
        xx21 = order - (xx21.abs() % order);
        println!("xx21 is negative");
        dbg!(xx21.clone());
    }
    else 
    {
        xx21 = xx21 % order;
        dbg!(xx21.clone());
    }

    let mut sl = (y1.clone()-y2.clone()) * xx21;
    sl = sl % order;
    if BigInt::is_negative(&sl) {
        sl = order - (sl.abs() % order);
        println!("sl is negative");
        dbg!(sl.clone());
    }
    else 
    {
        sl = sl % order;
        dbg!(sl.clone());
    }

    let mut s = (sl.clone() * sl.clone()) - x1.clone() - x2.clone();
    s=s % order;

    if BigInt::is_negative(&s) {
        s = order - (s.abs() % order);
        println!("s is negative");
        dbg!(s.clone());
    }

    assert_eq!(s, sum_s, "Sum_s and s check failed");
    println!("Sum_s and s successful");

    (s1, s2)
}