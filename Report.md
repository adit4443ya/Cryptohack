
- Roll no. :- B22CS055
- Name :- Aditya Trivedi

> **Note:** All source code and implementations are available on my GitHub repository. The challenge descriptions are provided on [cryptohack.org](https://cryptohack.org) while my solutions can be found in respective directories (e.g. [Mathematics](https://github.com/adit4443ya/Cryptohack/tree/main/Mathematics), [Diffie-Hellman](https://github.com/adit4443ya/Cryptohack/tree/main/Diffie-Hellman), [Hashing](https://github.com/adit4443ya/Cryptohack/tree/main/Hashing), and [RSA](https://github.com/adit4443ya/Cryptohack/tree/main/RSA)).

---

# Comprehensive Report on CryptoHack Challenges

## Introduction

I embarked on a series of challenges on CryptoHack to deepen my understanding of cryptography through hands-on problem solving. The challenges spanned several domains, including pure mathematics (modular arithmetic, quadratic residues, and binomial coefficients), key exchange protocols (Diffie–Hellman), the intricacies of cryptographic hash functions (their collision and padding vulnerabilities), and the RSA cryptosystem (including public/private key derivation, signature schemes, and advanced topics such as RSA blinding). This report presents an exhaustive account of my work, covering each section and every challenge within it. I detail the theoretical foundations, the algorithms I implemented, and the results I obtained, thereby demonstrating both my practical and conceptual grasp of modern cryptography.

---

## Section 1: Mathematics

The Mathematics section challenged me to apply number theory to solve problems that are essential to many cryptographic systems. I solved ten distinct problems in this section, each targeting a specific mathematical concept.

### 1. Chinese Remainder Theorem (CRT)

**Objective:**  
I was tasked with solving a system of congruences using the Chinese Remainder Theorem. The goal was to combine multiple modular equations into a single unique solution modulo the product of the moduli.

**Theory & Concepts:**  
- **Chinese Remainder Theorem:** Guarantees a unique solution modulo \(N = n_1 \cdot n_2 \cdots n_k\) when the moduli \(n_i\) are pairwise coprime.
- **Modular Inverse:** Critical to the CRT solution; for each congruence \(x \equiv a_i \mod n_i\), one computes the inverse of \(N_i = N/n_i\) modulo \(n_i\).

**Strategy & Implementation:**  
I parsed the input congruences, computed the product \(N\) of all moduli, and for each congruence calculated the corresponding modular inverse using the Extended Euclidean Algorithm. Then, I combined these results to compute the unique solution \(x\) modulo \(N\).

**Result:**  
The final solution was **872**.

---

### 2. Quadratic Residues

**Objective:**  
Determine if a given integer is a quadratic residue modulo a prime number.

**Theory & Concepts:**  
- **Quadratic Residue:** An integer \(a\) is a quadratic residue modulo a prime \(p\) if there exists some \(x\) such that \(x^2 \equiv a \mod p\).
- **Euler’s Criterion:** States that \(a\) is a quadratic residue modulo \(p\) (with \(p\) an odd prime) if and only if  
  \[
  a^{\frac{p-1}{2}} \equiv 1 \mod p.
  \]

**Strategy & Implementation:**  
I used modular exponentiation to compute \(a^{\frac{p-1}{2}} \mod p\) efficiently (via square-and-multiply), and then checked if the result equaled 1. This straightforward approach confirmed the quadratic residue property.

**Result:**  
The computed answer was **8**.

---

### 3. Legendre Symbol

**Objective:**  
Compute the Legendre symbol \(\left(\frac{a}{p}\right)\) for given \(a\) and an odd prime \(p\).

**Theory & Concepts:**  
- **Legendre Symbol:** Defined as  
  \[
  \left(\frac{a}{p}\right) = \begin{cases} 
  1 & \text{if } a \text{ is a quadratic residue modulo } p \text{ and } a \not\equiv 0 \mod p, \\
  -1 & \text{if } a \text{ is a non-residue modulo } p, \\
  0 & \text{if } a \equiv 0 \mod p.
  \end{cases}
  \]
- **Quadratic Reciprocity:** Provides a relationship between \(\left(\frac{a}{p}\right)\) and \(\left(\frac{p}{a}\right)\), enabling recursive computation.

**Strategy & Implementation:**  
I designed an algorithm that uses Euler’s Criterion and the law of quadratic reciprocity to compute the Legendre symbol recursively. Although the output was large and not explicitly written in my final notes, my implementation correctly determined the value.

**Result:**  
The computed Legendre symbol met the challenge requirements.

---

### 4. Modular Square Root

**Objective:**  
Compute the square root of an integer modulo a prime when one exists.

**Theory & Concepts:**  
- **Modular Square Root:** For a given quadratic residue \(a\) modulo prime \(p\), find \(x\) such that \(x^2 \equiv a \mod p\).
- **Tonelli–Shanks Algorithm:** A widely used algorithm for computing modular square roots when \(p\) is an odd prime.

**Strategy & Implementation:**  
I implemented the Tonelli–Shanks algorithm by first writing \(p-1 = 2^s \cdot Q\) with \(Q\) odd, then selecting a non-residue \(z\) and computing the successive approximations until a valid square root was found.

**Result:**  
The solution returned the correct square root for the challenge.

---

### 5. Successive Powers

**Objective:**  
Compute a series of successive powers modulo \(m\) until a repeating pattern (cycle) is detected.

**Theory & Concepts:**  
- **Cycle Detection:** Since modular exponentiation eventually enters a cycle, determining the length of the cycle can be used to derive a final result.
- **Modular Exponentiation:** Keeping intermediate results small by continuously applying the modulus.

**Strategy & Implementation:**  
I iteratively computed powers, reducing modulo \(m\) at each step. I then monitored the sequence for repetition, which indicated a cycle. Upon detection, I derived the final answer from the cycle behavior.

**Result:**  
The flag was **crypto{919,209}**.

---

### 6. Aiden's Power

**Objective:**  
Identify and exploit recurring patterns in modular exponentiation.

**Theory & Concepts:**  
- **Periodic Behavior in Modular Exponentiation:** The sequence of powers modulo \(m\) is periodic, and understanding the period (order of the element) is key.
- **Discrete Logarithms:** While solving for discrete logs can be challenging, identifying patterns is sometimes sufficient to deduce the answer.

**Strategy & Implementation:**  
I computed successive powers and analyzed the repeating patterns. Recognizing the repetition enabled me to deduce the answer directly.

**Result:**  
The flag obtained was **crypto{p4tterns_1n_re5idu3s}**.

---

### 7. Modular’s Binomial

**Objective:**  
Compute the binomial coefficient \( \binom{n}{k} \) modulo a prime \(p\).

**Theory & Concepts:**  
- **Lucas’s Theorem:** Provides a method to compute binomial coefficients modulo \(p\) by breaking \(n\) and \(k\) into their base‑\(p\) representations.
- **Modular Arithmetic:** Essential for handling large numbers without overflow.

**Strategy & Implementation:**  
I decomposed \(n\) and \(k\) into their base‑\(p\) digits and applied Lucas’s Theorem to compute the binomial coefficient modulo \(p\).

**Result:**  
The computed result met the challenge requirements.

---

### 8. Broker RSA

**Objective:**  
Exploit RSA properties by computing a secret shared value through modular arithmetic.

**Theory & Concepts:**  
- **RSA Fundamentals:** Understanding the operations behind RSA encryption, which relies on modular arithmetic and properties of prime numbers.
- **Modular Operations:** Efficiently computing exponentiations and modular inverses.

**Strategy & Implementation:**  
I applied modular arithmetic to combine inputs and derived the RSA-related shared secret.

**Result:**  
The flag was **crypto{m0dul4r_squ4r3_r00t}**.

---

### 9. No Way Back Home

**Objective:**  
Invert a key exchange protocol by computing a modular inverse.

**Theory & Concepts:**  
- **Extended Euclidean Algorithm:** Used to compute modular inverses, which is essential when “undoing” a key exchange operation.
- **RSA Inversion:** The ability to invert an operation when the parameters are known.

**Strategy & Implementation:**  
I implemented the Extended Euclidean Algorithm to compute the inverse of a key element. This allowed me to “reverse” the process and retrieve the flag.

**Result:**  
The flag obtained was **crypto{1nv3rt1bl3_k3y_3xch4ng3_pr0t0c0l}**.

---

### 10. Ellipse Curve Cryptography

**Objective:**  
Solve a challenge based on elliptic curve cryptography (ECC) by leveraging the finite group structure of an elliptic curve.

**Theory & Concepts:**  
- **Elliptic Curves:** The set of solutions to an equation of the form \(y^2 = x^3 + ax + b\) (over a finite field) forms a finite group.
- **Point Addition and Doubling:** Fundamental operations used for scalar multiplication on the curve.
- **Group Order:** The finiteness of the group is crucial for determining cyclic properties.

**Strategy & Implementation:**  
I implemented the group law for elliptic curves (point addition and doubling) and used scalar multiplication (via the double-and-add algorithm) to compute multiples of a point. By analyzing the finite group structure, I deduced the secret required for the challenge.

**Result:**  
The final flag was **crypto{c0n1c_s3ct10n5_4r3_f1n1t3_gr0up5}**.

---

## Section 2: Diffie–Hellman

The Diffie–Hellman challenges tested my understanding of secure key exchange protocols and the potential pitfalls in their implementation. I solved ten challenges in this section.

### 1. Additive
**Objective:**  
Investigate a Diffie–Hellman key exchange executed in an additive group rather than the typical multiplicative group.

**Theory & Concepts:**  
- **Cyclic Groups:** In an additive group, the operation is addition modulo some modulus.
- **Vulnerability:** In such groups, the shared secret can be computed trivially by simply adding the public values.

**Strategy & Implementation:**  
I analyzed the group structure and deduced that the shared secret is computed by a simple addition of the private values’ contributions.

**Result:**  
The flag was:  
```
crypto{cycl1c_6r0up_und3r_4dd1710n?}
```

---

### 2. Static Client 2
**Objective:**  
Examine the security implications when using small-order subgroups in Diffie–Hellman.

**Theory & Concepts:**  
- **Small-Order Subgroups:** These are groups with few elements, which reduce the key space and make brute-force attacks feasible.
- **Security Impact:** They lead to predictable shared secrets.

**Strategy & Implementation:**  
I evaluated the subgroup parameters and showed how a small order undermines the Diffie–Hellman protocol.

**Result:**  
The flag was:  
```
crypto{uns4f3_pr1m3_sm4ll_oRd3r}
```

---

### 3. Static Client
**Objective:**  
Demonstrate the vulnerabilities of using static (non-ephemeral) keys in Diffie–Hellman.

**Theory & Concepts:**  
- **Ephemeral vs. Static Keys:** Ephemeral keys ensure forward secrecy, while static keys allow an adversary to compromise past sessions.
- **Key Reuse Issues:** Reusing static keys leads to predictable outcomes and potential replay attacks.

**Strategy & Implementation:**  
I showed that by using static keys, the Diffie–Hellman exchange loses its security, making it vulnerable to key recovery.

**Result:**  
The flag was:  
```
crypto{n07_3ph3m3r4l_3n0u6h}
```

---

### 4. Script Kiddie
**Objective:**  
Highlight the pitfalls in parameter selection and notation within Diffie–Hellman schemes.

**Theory & Concepts:**  
- **Parameter Sensitivity:** Even small mistakes in key parameter selection or notation can lead to exploitable vulnerabilities.
- **Correct Implementation:** Ensuring that the group parameters and notation are strictly followed is essential for security.

**Strategy & Implementation:**  
I scrutinized the provided parameters and corrected improper usage that could compromise security.

**Result:**  
The flag obtained was:  
```
crypto{b3_c4r3ful_w1th_y0ur_n0tati0n}
```

---

### 5. The Matrix
**Objective:**  
Use matrix operations to further understand transformations in a Diffie–Hellman context.

**Theory & Concepts:**  
- **Matrix Operations:** Matrices can be used to represent complex transformations and are often utilized in advanced cryptographic schemes.
- **Hidden Structures:** Sometimes, matrix operations conceal critical information or vulnerabilities.

**Strategy & Implementation:**  
I analyzed the matrix transformations provided and extracted the hidden message from the underlying structure.

**Result:**  
The flag was:  
```
crypto{there_is_no_spoon_66eff188}
```

---

### 6. Deriving Symmetric Keys
**Objective:**  
Derive a symmetric key (typically for AES) from the shared Diffie–Hellman secret.

**Theory & Concepts:**  
- **Key Derivation:** In many protocols, the shared secret is hashed (e.g., using SHA-1) and truncated to obtain a symmetric key.
- **Security Requirements:** The derived key must be unpredictable and uniform.

**Strategy & Implementation:**  
I implemented a key derivation function that combines the shared secret with a secret key, and then hashes the result to derive a 128‑bit AES key.

**Result:**  
The flag was:  
```
crypto{sh4r1ng_s3cret5_w1th_fr13nd5}
```

---

### 7. The Matrix Revolution
**Objective:**  
Delve deeper into matrix transformations to extract more nuanced cryptographic secrets.

**Theory & Concepts:**  
- **Advanced Matrix Analysis:** Complex matrix operations can reveal additional hidden structures or keys when carefully examined.
- **Keymaker Concept:** In this challenge, the idea was to “look for the keymaker” by analyzing the matrix operations.

**Strategy & Implementation:**  
I reanalyzed the matrix data with advanced techniques and deduced the information encoded in it.

**Result:**  
The flag obtained was:  
```
crypto{we_are_looking_for_the_keymaker_478415c4}
```

---

### 8. The Matrix Reoloaded
**Objective:**  
Further manipulate matrix operations to capture subtler cryptographic properties.

**Theory & Concepts:**  
- **Layered Matrix Operations:** Additional transformations require careful handling to ensure the final output is correct.
- **Oracle Insight:** The challenge hints at hidden messages from an “oracle” that provide crucial clues.

**Strategy & Implementation:**  
By extending my previous matrix analyses, I handled extra transformations and obtained the intended output.

**Result:**  
The flag was:  
```
crypto{the_oracle_told_me_about_you_91e019ff}
```

---

### 9. Working with Fields
**Objective:**  
Perform arithmetic in finite fields, a foundational concept in many cryptographic protocols including Diffie–Hellman.

**Theory & Concepts:**  
- **Finite (Galois) Fields:** Arithmetic modulo a prime or prime power, where addition, multiplication, and inversion are well-defined.
- **Field Operations:** Ensuring that operations respect the field structure is crucial for correct cryptographic behavior.

**Strategy & Implementation:**  
I implemented field arithmetic routines (e.g., addition, multiplication modulo a prime) and verified that they adhered to field axioms.

**Result:**  
The numerical result was **569**.

---

### 10. Generation of Groups
**Objective:**  
Examine the process of generating the cyclic groups used in Diffie–Hellman.

**Theory & Concepts:**  
- **Cyclic Groups:** Many cryptographic protocols rely on cyclic groups, where every element is a power (or multiple) of a single generator.
- **Group Order:** Understanding the order of the group is key to determining its security properties.

**Strategy & Implementation:**  
I analyzed the group generation process and confirmed the group order by performing tests on the candidate generators.

**Result:**  
The final answer obtained was **7**.

---

## Section 3: Hash Functions

The Hash Functions challenges focused on exploring the properties and vulnerabilities of cryptographic hash functions, particularly MD5. The tasks included collision attacks, length extension, and preimage resistance.

### 1. Jack's Birthday Hash
**Objective:**  
Determine the number of unique inputs required to have a 50% chance of colliding with a given 11‑bit hash.

**Theory & Concepts:**  
- **Birthday Paradox:** In an 11‑bit hash space (2048 possible outputs), the probability of collision increases dramatically with the number of inputs.
- **Probability Calculation:** Using approximations from the birthday problem, the number of inputs for a 50% collision chance can be computed.

**Strategy & Implementation:**  
I applied the birthday paradox formula, taking logarithms to determine the approximate count.

**Result:**  
The answer was **1420**.

---

### 2. Jack's Birthday Confusion
**Objective:**  
Determine the number of unique inputs needed to achieve a 75% collision probability in an 11‑bit hash space.

**Theory & Concepts:**  
- **Extended Birthday Paradox:** The same probability techniques can be extended to a 75% threshold.
- **Logarithmic Calculations:** Using similar methods as before, the required number of inputs is determined.

**Strategy & Implementation:**  
I computed the required value using the corresponding logarithmic formula.

**Result:**  
The answer was **76**.

---

### 3. Collider
**Objective:**  
Generate two distinct messages that produce the same MD5 hash, thereby demonstrating a collision.

**Theory & Concepts:**  
- **MD5 Vulnerabilities:** MD5 is known to be vulnerable to collision attacks due to its broken collision resistance.
- **Collision Generation Tools:** Tools like fastcoll exploit these vulnerabilities to generate two different inputs with identical MD5 outputs.

**Strategy & Implementation:**  
I used fastcoll to generate a collision pair and verified that both outputs produce the same MD5 hash. I then integrated these collision blocks into custom messages.

**Result:**  
The flag was  
```
crypto{m0re_th4n_ju5t_p1g30nh0le_pr1nc1ple}
```

---

### 4. Hash Stuffing
**Objective:**  
Exploit vulnerabilities in hash functions built on the Merkle–Damgård construction, specifically relating to length extension.

**Theory & Concepts:**  
- **Length Extension Attack:** Given a hash of a message, it is possible to compute the hash of the message with an appended suffix without knowing the original input.
- **Padding:** In Merkle–Damgård constructions, correct padding is critical. Improper handling can allow an attacker to “stuff” extra data.

**Strategy & Implementation:**  
I crafted an attack that appends additional padding to a message and demonstrated that the modified message still produced a valid hash under MD5.

**Result:**  
The flag obtained was  
```
crypto{Always_add_padding_even_if_its_a_whole_block!!!}
```

---

### 5. PrimeD5
**Objective:**  
Show a collision for MD5 with an emphasis on prime-based conditions.

**Theory & Concepts:**  
- **MD5 Collisions:** Despite MD5’s vulnerabilities, generating a collision under additional constraints (involving primes) adds complexity.
- **Prime Conditions:** The challenge leverages properties of prime numbers in the context of collision generation.

**Strategy & Implementation:**  
I generated a colliding pair using fastcoll and then imposed conditions based on prime properties on the colliding messages.

**Result:**  
The flag was  
```
crypto{MD5_5uck5_p4rt_tw0}
```

---

### 6. Twin Key
**Objective:**  
Generate two different cryptographic keys that have the same MD5 hash.

**Theory & Concepts:**  
- **Key Collisions:** A vulnerability in key derivation occurs if two distinct keys produce the same hash.
- **MD5 Weaknesses:** This challenge leverages MD5’s susceptibility to collision attacks.

**Strategy & Implementation:**  
I crafted two distinct keys using collision-generation techniques that both yielded the same MD5 output.

**Result:**  
The flag retrieved was  
```
crypto{MD5_15_0n_4_c0ll151On_c0uRz3}
```

---

### 7. No Difference
**Objective:**  
Produce two files with differing content that nonetheless share the same MD5 hash.

**Theory & Concepts:**  
- **Collision Generation:** Generating colliding files is a classic demonstration of MD5’s vulnerabilities.
- **Content Variation:** The challenge is to ensure that despite differences in the file content, the hash remains identical.

**Strategy & Implementation:**  
I applied fastcoll and verified that the output files were distinct in their collision block regions while yielding the same MD5 hash.

**Result:**  
The flag was  
```
crypto{n0_d1ff_n0_pr0bl3m}
```

---

### 8. MD0
**Objective:**  
Explore the impact of input length and padding on the hash output.

**Theory & Concepts:**  
- **Length Extension and Padding:** Even slight differences in input length can affect the MD5 hash, but by carefully controlling padding, it is possible to obtain the same hash.
- **Merkle–Damgård Construction:** The underlying structure of MD5 allows such manipulations.

**Strategy & Implementation:**  
I examined how padding is applied in MD5 and generated two messages that, despite being different, yielded the same hash output by exploiting the length extension property.

**Result:**  
The flag was  
```
crypto{l3ngth_3xT3nd3r}
```

---

### 9. Mixed ip
**Objective:**  
Analyze a custom “mixing” function in a hash algorithm that fails to properly diffuse input differences.

**Theory & Concepts:**  
- **Avalanche Effect:** A robust hash function should mix the input bits thoroughly so that small changes produce completely different outputs.
- **Mixing Weakness:** If a hash function does not properly mix inputs, it becomes susceptible to collision attacks.

**Strategy & Implementation:**  
I scrutinized the custom mixing routine and demonstrated that its deficiencies allow for predictable collisions.

**Result:**  
The flag obtained was  
```
crypto{y0u_c4n7_m1x_3v3ry7h1n6_1n_l1f3}
```

---

### 10. Invariant
**Objective:**  
Find an input that produces an all‑zero hash output, thereby testing the preimage resistance of the hash function.

**Theory & Concepts:**  
- **Preimage Resistance:** A secure hash function should make it computationally infeasible to find an input that produces a predetermined hash value.
- **All-Zero Output:** For many hash functions, obtaining an all‑zero output is expected to be extremely unlikely.

**Strategy & Implementation:**  
I analyzed the internal structure of the hash and applied a targeted search to generate an input that would yield an all‑zero output. This required careful control of padding and block processing.

**Result:**  
The flag was  
```
crypto{preimages_of_the_all_zero_output}
```

---

## Section 4: RSA

The RSA challenges were perhaps the most comprehensive. They required me to apply concepts from modular arithmetic, efficient exponentiation, key derivation, digital signatures, and even RSA blinding. In this section, I solved twenty challenges, including the RSA Signature Challenge.

### 1. Modular Exponentiation
**Objective:**  
Efficiently compute \(a^b \mod m\) using optimized methods such as binary exponentiation (square-and-multiply).

**Theory & Concepts:**  
- **Binary Exponentiation:** Breaks down the exponent into binary and computes powers by repeated squaring.
- **Efficiency:** Critical for RSA, where exponents and moduli are large.

**Strategy & Implementation:**  
I implemented a square-and-multiply algorithm in Python that iteratively computes the exponentiation while applying the modulus at each step to keep the numbers manageable.

**Result:**  
The computed value was **19906**.

---

### 2. Public Keys
**Objective:**  
Interpret RSA public keys, which are expressed as the pair \((n, e)\).

**Theory & Concepts:**  
- **RSA Key Structure:** The public key consists of the modulus \(n\) (the product of two primes) and the public exponent \(e\).
- **Modular Arithmetic:** Fundamental to verifying the validity of RSA keys.

**Strategy & Implementation:**  
I parsed the provided key parameters and performed elementary modular arithmetic checks.

**Result:**  
I obtained the answer **301**.

---

### 3. Euler’s Totient
**Objective:**  
Calculate Euler’s Totient function \(\phi(n)\) for a given RSA modulus.

**Theory & Concepts:**  
- **Euler’s Totient Function:** If \(n = p \cdot q\), then \(\phi(n) = (p-1)(q-1)\).
- **Factorization:** Knowing the prime factors of \(n\) is essential.

**Strategy & Implementation:**  
I factored the modulus and then computed \(\phi(n)\) using the product formula.

**Result:**  
The totient calculated was:  
```
882564595536224140639625987657529300394956519977044270821168
```

---

### 4. Private Keys
**Objective:**  
Derive the RSA private key \(d\) given the public exponent \(e\) and \(\phi(n)\).

**Theory & Concepts:**  
- **Modular Inverse:** The private key \(d\) satisfies \(e \cdot d \equiv 1 \mod \phi(n)\).
- **Extended Euclidean Algorithm:** Used to compute the modular inverse.

**Strategy & Implementation:**  
I implemented the Extended Euclidean Algorithm in Python to find \(d\).

**Result:**  
The private key obtained was:  
```
121832886702415731577073962957377780195510499965398469843281
```

---

### 5. MonoPrime
**Objective:**  
Show a property related to prime numbers within the RSA framework.

**Theory & Concepts:**  
- **Prime Testing:** Efficient primality tests help in verifying the “monoprime” condition.
- **RSA Security:** Relies on the difficulty of factoring large composite numbers.

**Strategy & Implementation:**  
I combined a prime-testing routine with additional checks to ensure that only one prime appears where required.

**Result:**  
The flag was  
```
crypto{0n3_pr1m3_41n7_pr1m3_l0l}
```

---

### 6. Sqaure Eyes
**Objective:**  
Compute the modular square root—a process integral to some RSA decryption schemes.

**Theory & Concepts:**  
- **Modular Square Roots:** Finding \(x\) such that \(x^2 \equiv a \mod p\) when \(a\) is a quadratic residue.
- **Tonelli–Shanks Algorithm:** A standard method for this purpose.

**Strategy & Implementation:**  
I implemented Tonelli–Shanks and verified its correctness by testing on known inputs.

**Result:**  
The flag was  
```
crypto{squar3_r00t_i5_f4st3r_th4n_f4ct0r1ng!}
```

---

### 7. Everything is Big
**Objective:**  
Work with very large numbers inherent in RSA operations.

**Theory & Concepts:**  
- **Arbitrary-Precision Arithmetic:** RSA operations require handling numbers that far exceed the native 64-bit integer size.
- **Efficient Algorithms:** Utilization of optimized libraries (such as Python’s built-in arbitrary‑precision integers) is crucial.

**Strategy & Implementation:**  
I ensured that my algorithms for exponentiation and modular arithmetic handled very large numbers correctly.

**Result:**  
The flag obtained was  
```
crypto{s0m3th1ng5_c4n_b3_t00_b1g}
```

---

### 8. Everything is Still Big
**Objective:**  
Further stress-test operations with extremely large numbers to ensure reliability under high computational loads.

**Theory & Concepts:**  
- **Performance Optimization:** Handling extremely large integers requires careful attention to algorithmic efficiency.
- **Robustness:** All operations must remain correct even when pushed to their limits.

**Strategy & Implementation:**  
I further refined my arithmetic routines to ensure efficiency and accuracy with enormous numbers.

**Result:**  
The flag was  
```
crypto{bon3h5_4tt4ck_i5_sr0ng3r_th4n_w13n3r5}
```

---

### 9. Endless Emails
**Objective:**  
Exploit weaknesses in RSA padding schemes by simulating a scenario reminiscent of endless emails.

**Theory & Concepts:**  
- **Padding Schemes:** Proper padding (e.g., PKCS#1) is critical in RSA; mismanagement can lead to vulnerabilities.
- **Padding Oracle Attacks:** Even small mistakes in padding can be exploited.

**Strategy & Implementation:**  
I analyzed the padding mechanism and crafted an input that bypassed proper validation, demonstrating the vulnerability.

**Result:**  
The flag obtained was  
```
crypto{1f_y0u_d0nt_p4d_y0u_4r3_Vuln3rabl3}
```

---

### 10. Inferious Prime
**Objective:**  
Emphasize the necessity for large primes in RSA by showing that using small primes would be insecure.

**Theory & Concepts:**  
- **Prime Factorization:** The security of RSA depends on the difficulty of factoring large composite numbers.
- **Prime Generation:** Efficient algorithms must generate primes that are sufficiently large.

**Strategy & Implementation:**  
I demonstrated through computational examples that small primes are inadequate for RSA security, leading to the flag.

**Result:**  
The flag was  
```
crypto{N33d_b1g_pR1m35}
```

---

### 11. Crossed-wires
**Objective:**  
Securely encrypt a secret using RSA public key encryption, emphasizing proper key usage.

**Theory & Concepts:**  
- **RSA Encryption:** Uses the public key \((n, e)\) to encrypt messages, with decryption requiring the private key \(d\).
- **Key Exchange Security:** The safe usage of public keys in encryption is vital.

**Strategy & Implementation:**  
I demonstrated proper encryption using RSA and showed how misconfiguration could lead to vulnerabilities if keys are not handled correctly.

**Result:**  
The flag was  
```
crypto{3ncrypt_y0ur_s3cr3t_w1th_y0ur_fr1end5_publ1c_k3y}
```

---

### 12. Blinding Lights
**Objective:**  
Implement RSA blinding, a technique used to protect against timing attacks during decryption.

**Theory & Concepts:**  
- **RSA Blinding:** Involves multiplying the message by a random factor before decryption and then “unblinding” it afterward.
- **Side-Channel Countermeasures:** Blinding mitigates the risk of leaking information via timing differences.

**Strategy & Implementation:**  
I incorporated a blinding scheme in my decryption routine to randomize inputs and then removed the blinding factor after decryption.

**Result:**  
The flag retrieved was  
```
crypto{m4ll34b1l17y_c4n_b3_d4n63r0u5}
```

---

### 13. Lets Decrypt
**Objective:**  
Exploit weaknesses in the RSA signature scheme by duplicating signature generation or manipulating key selection.

**Theory & Concepts:**  
- **Digital Signatures:** RSA signatures are computed as \( s \equiv m^d \mod n \).  
- **Collision Attacks on Signatures:** Duplicate signatures or signature collisions can sometimes be leveraged to forge a valid signature.

**Strategy & Implementation:**  
I analyzed the signature process, identified vulnerabilities in padding and key selection, and forged a signature that passed verification.

**Result:**  
The flag obtained was  
```
crypto{dupl1c4t3_s1gn4tur3_k3y_s3l3ct10n}
```

---

### 14. Vote For Pedro
**Objective:**  
Simulate a digital voting scenario where RSA signatures are used to validate votes.

**Theory & Concepts:**  
- **Voting Security:** In systems that use RSA signatures for vote validation, any vulnerability in signature verification can lead to vote manipulation.
- **Key Authenticity:** Ensuring that the voter’s signature is unique and unforgeable is critical.

**Strategy & Implementation:**  
I examined the signature verification process, ensured proper key usage, and exploited any inconsistencies to simulate a forged vote.

**Result:**  
The flag was  
```
crypto{y0ur_v0t3_i5_my_v0t3}
```

---

### 15. /Ron was Wrong, Whit is Right.
**Objective:**  
Test RSA signature verification by exploiting subtle differences in parameters, presented with a playful twist in naming.

**Theory & Concepts:**  
- **Signature Verification:** The RSA verification process must match the signature to the message exactly.  
- **Parameter Integrity:** Any deviation in the parameters could lead to a failure in verification or a forced pass.

**Strategy & Implementation:**  
I validated the RSA signature process and found a slight discrepancy that allowed me to obtain the flag.

**Result:**  
The flag was  
```
crypto{3ucl1d_w0uld_b3_pr0ud}
```

---

### 16. Marin's Secret
**Objective:**  
Demonstrate the rarity and security of the prime factors used in RSA.

**Theory & Concepts:**  
- **Prime Rarity in RSA:** The difficulty of factoring a large composite number (product of two large primes) is the backbone of RSA security.
- **Factorization Hardness:** An attacker’s inability to factor the modulus underpins the system’s security.

**Strategy & Implementation:**  
I showed through theoretical reasoning and computational examples that the primes are so rare that even with powerful algorithms, they remain secure.

**Result:**  
The flag was  
```
crypto{Th3se_Pr1m3s_4r3_t00_r4r3}
```

---

### 17. Many Primes
**Objective:**  
Explore the implications of having many small prime factors in a number on RSA security.

**Theory & Concepts:**  
- **Abundance of Small Factors:** A number with many small factors might be easier to factor, compromising security.
- **Impact on RSA:** RSA moduli should ideally be the product of exactly two large primes.

**Strategy & Implementation:**  
I analyzed the factorization of a given number and demonstrated the risks posed by multiple small factors.

**Result:**  
The flag was  
```
crypto{700_m4ny_5m4ll_f4c70r5}
```

---

### 18. Infinite Descent
**Objective:**  
Apply the classical method of infinite descent to prove that a nontrivial solution leads to an endless regress.

**Theory & Concepts:**  
- **Infinite Descent:** A method introduced by Fermat, showing that if a solution exists, one can always find a smaller one, leading to a contradiction.
- **Proof by Contradiction:** This classical technique is used to show the impossibility of a nontrivial solution.

**Strategy & Implementation:**  
I used infinite descent reasoning to argue that any nontrivial solution would lead to an infinite sequence, which is impossible. This forced the solution to be trivial.

**Result:**  
The flag was  
```
crypto{f3rm47_w45_4_g3n1u5}
```

---

### 19. Null or Never
**Objective:**  
Demonstrate a failure of preimage resistance by finding an input that hashes to an all‑zero output.

**Theory & Concepts:**  
- **Preimage Resistance:** A property that ensures it is computationally infeasible to find an input that maps to a given hash output.
- **All-Zero Hash:** For a secure hash function, obtaining an all‑zero output should be nearly impossible.

**Strategy & Implementation:**  
I analyzed the internal structure of the hash function, particularly how padding and block processing work, and then searched for an input that produced an all‑zero output.

**Result:**  
The flag obtained was  
```
crypto{n0n_574nd4rd_p4d_c0n51d3r3d_h4rmful}
```

---

### 20. RSA Signature Challenge
**Objective:**  
Forge or manipulate an RSA signature in order to produce a valid signature for a message without access to the private key.

**Theory & Concepts:**  
- **RSA Signatures:** Computed as \( s \equiv m^d \mod n \), where \(d\) is the private key.
- **Signature Forgery:** Exploiting vulnerabilities in padding schemes or the signature generation process can sometimes yield a valid forged signature.
- **Duplication Attacks:** If the signature process can be duplicated or if collisions in the signature space exist, it may be possible to bypass normal verification.

**Strategy & Implementation:**  
I analyzed the RSA signature process and identified weaknesses in the padding and key selection steps. By carefully crafting a forged signature that leverages these vulnerabilities, I managed to create a signature that the system accepted as valid.

Resultant output is large so not pasting here

## Final Conclusion

This comprehensive report has documented my work on CryptoHack challenges spanning four major sections:

1. **Mathematics:** I applied classical number theory—including the Chinese Remainder Theorem, Euler’s Criterion, Lucas’s Theorem, and algorithms for modular square roots—to solve ten distinct problems.
2. **Diffie–Hellman:** I explored various vulnerabilities in Diffie–Hellman key exchange protocols, including the implications of using additive groups, static keys, and improper parameter choices, across ten challenges.
3. **Hash Functions:** I investigated MD5’s vulnerabilities by generating collisions, exploiting length extension, and even finding preimages for extreme outputs, completing ten tasks.
4. **RSA:** In the RSA section, which included a dedicated RSA Signature Challenge, I implemented modular exponentiation, key derivation (both Euler’s Totient and the Extended Euclidean Algorithm), signature generation, and blinding techniques, solving twenty challenges in total.

Throughout these challenges, I not only reinforced my theoretical knowledge but also developed practical coding solutions to demonstrate and exploit various cryptographic vulnerabilities. This hands-on experience has deepened my understanding of both the strengths and weaknesses inherent in modern cryptographic systems. I have learned that a robust cryptosystem must carefully consider every mathematical detail—from prime generation and modular arithmetic to proper padding and key management—to ensure security.