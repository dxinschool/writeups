# Bivariate Copper - Writeup

## Challenge Overview

The "Bivariate Copper" challenge involves recovering a flag hidden within a set of modular relations. We are provided with:

- An RSA-encrypted message with a 1049-bit modulus $N$.
- A 64-bit value $k$.
- Two 512-bit values $r_1, r_2$.
- The upper bits of two values $t_1, t_2$, where:
  $$t_1 \equiv k(m + r_1)^{-1} \pmod p$$
  $$t_2 \equiv k(m + r_2)^{-1} \pmod p$$
  and $p$ is a large prime factor of $N$.

The task is to factor $N$, decrypt the RSA message, and use the leaked bits of $t_1, t_2$ to recover the flag $m$ via a bivariate Coppersmith-style attack.

## Solving Steps

### 1. Factoring the RSA Modulus $N$

The RSA modulus $N$ is 1049 bits long. Testing for small factors reveals a small prime factor $q$:

- $q = 23,520,857$ (a 25-bit prime)
- $p = N // q$ (a 1024-bit prime)

This factorization provides the modulus $p$ used in the $t_1, t_2$ relations.

### 2. RSA Decryption

With $p$ and $q$, we calculate $\phi(N) = (p-1)(q-1)$ and the private exponent $d = e^{-1} \pmod{\phi(N)}$. Decrypting the ciphertext $c$:

- $m_{rsa} = c^d \pmod N$
- Decoded hint: `b'Hurry up and go smelt copper!'`

The hint points towards a Coppersmith attack.

### 3. Deriving the Bivariate Equation

The relations modulo $p$ are:

1. $t_1(m + r_1) \equiv k \pmod p$
2. $t_2(m + r_2) \equiv k \pmod p$

Eliminating $m$:
$$(r_2 - r_1) t_1 t_2 \equiv k(t_1 - t_2) \pmod p$$

Let $t_1 = T_1 + x$ and $t_2 = T_2 + y$, where $T_1, T_2$ are the known upper bits and $x, y$ are the small unknowns ($0 \le x, y < 2^{244}$). Substituting these into the equation yields a bivariate polynomial:
$$f(x, y) = xy + Bx + Cy + A \equiv 0 \pmod p$$
where $A, B, C$ are constants derived from $T_1, T_2, r_1, r_2, k$.

### 4. Lattice Construction and Solving (SageMath)

Using SageMath, we can find the small roots $(x, y)$ efficiently. We define the bounds $X = Y = 2^{244}$ and construct a lattice based on the polynomial $f(x, y)$.

The basis matrix $M$:
$$
M = \begin{pmatrix}
p & 0 & 0 & 0 \\
0 & pX & 0 & 0 \\
0 & 0 & pY & 0 \\
A & BX & CY & XY
\end{pmatrix}
$$

Running LLL on this matrix yields short vectors corresponding to polynomials $g_i(x, y)$ that have $(x, y)$ as a root over the integers. We can then find the intersection of two such polynomials using resultants:

```python
P.<x, y> = PolynomialRing(ZZ)
g1 = polys[0]
g2 = polys[1]
res = g1.resultant(g2, y)
roots_x = res.univariate_polynomial().roots()
```

### 5. Flag Recovery

After finding the root $x$, we compute $t_1 = T_1 + x$ and recover $m$:
$$m = (k \cdot t_1^{-1} - r_1) \pmod p$$
Converting $m$ to bytes reveals the flag: `flag{H4hAHhhHh4_c0pP3r_N07_v1OI3n7_3n0uGh}`.
