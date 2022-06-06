## Diffie–Hellman key exchange with an authenticated channel
This code example mimic the basic scenario where Alice wants to establish DDH key exchange with Bob in an authenticated channel.

### Procedure
1. Alice first computes a big prime(recommended 256 bytes) `p` where `(p-1)/2=q` is also a prime number. The prime number `p`
   is used to form a cyclic group `G` whose order is `m=p-1`.
2. By the group theorem, any group element `g` of `G` with order `i` must satisfy `i|m`; that is, `i|2, q, 2q`.
   Even though `g` with order `q` is not a generator of `G`, it is still safe since the number is big enough.
3. Alice randomly picks a generator `g` and `x` and sends `(G,g,m,g^x)` to Bob. `g^x` here is Alice's public key, and `x` is the private key.
4. Bob uses the information to generate his own key, and sign the public key with RSA signature.
5. Bob sends `(g^y, Sign(g^y))` to Alice.
6. Alice verifies the signature `Sign(g^y)` with Bob's sign public key(Alice has it).
7. If signature matches, Alice and Bob generates the symmetric key `g^(xy)` and DDH key exchange is completed.

### Running time
The running time depends mostly on the prime number generator. With 128-byte prime number, it takes about 10 minutes to generate a valid prime number.
Here the code example has size of 16 bytes, which only takes about 5 seconds to generate.