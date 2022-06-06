import os
import random
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.exceptions import InvalidSignature


class DhKey:
    def __init__(self):
        self.peer_sign_public_key = None
        self.my_enc_public_key = None
        self.my_enc_private_key = None
        self.symmetric_key = None

        self.prime, self.order, self.generator = self.generate_enc_keys()

    def generate_enc_keys(self):
        # Generate prime number
        print('Getting a big prime number....')
        p, q = 0, 0
        # p must be a prime and p-1=2q where q must also be a prime
        while not self.is_prime(p) or not self.is_prime(q):
            p = int.from_bytes(os.urandom(16), byteorder="big")
            q = (p-1)//2

        while True:
            # From 1 to p-1=2q
            generator = random.randint(1, p - 1)

            # The order of the group element must divide 2q
            # The order must be 2, q or 2q
            print(f'Big prime is {p}')
            if pow(generator, 2, p) == 1:
                print(f'Subgroup element is {generator} but the order is 2, too small...')
                continue
            elif pow(generator, q, p) == 1:
                order = q
                print(f'Subgroup element is {generator} and the order is {q}, even though it is not a generator but is still big enough!')
            elif pow(generator, p-1, p) == 1:
                order = p-1
                print(f'Generator is {generator} and the order is {p-1}, found a generator!')

            break

        # From 0 to order-1 because (generator^order) = 1 by definition
        private_key = random.randint(0, order-1)
        # Generate key pair for key exchange
        self.my_enc_public_key, self.my_enc_private_key = pow(generator, private_key, p), private_key
        return p, order, generator

    def generate_symmetric_key(self, peer_enc_public_key):
        self.symmetric_key = pow(peer_enc_public_key, self.my_enc_private_key, self.prime)

    def verify_public_key(self, peer_sign_public_key, signature, message):
        try:
            peer_sign_public_key.verify(
                signature,
                message,
                padding.PSS(
                    mgf=padding.MGF1(hashes.SHA256()),
                    salt_length=padding.PSS.MAX_LENGTH
                ),
                hashes.SHA256()
            )
            return True
        except InvalidSignature as invalid:
            return False
        except Exception as e:
            print(e)
            raise e

    # Primality test with Fermat's little Theorem
    def is_prime(self, p):
        if p == 1:
            return False
        if p == 2:
            return True

        if p % 2 == 0:
            return False

        # Try five times
        for _ in range(5):
            elm = random.randint(1, p - 1)
            if pow(elm, p - 1, p) != 1:
                # print(f'fail {p}')
                return False

        return True


class DHkeyReceiver:
    def __init__(self, prime, order, generator, peer_enc_public_key):
        self.peer_enc_public_key = peer_enc_public_key
        self.my_enc_public_key = None
        self.my_enc_private_key = None
        self.symmetric_key = None
        self.prime = prime
        # Generate a pair key for signing
        self.my_sign_private_key = rsa.generate_private_key(
            public_exponent=65537,
            key_size=2048,
        )
        self.my_sign_public_key = self.my_sign_private_key.public_key()

        # Generate key pair for key exchange
        self.generate_enc_keys(prime, order, generator)

    def generate_enc_keys(self, prime, order, generator):
        private_key = random.randint(0, order-1)

        self.my_enc_public_key, self.my_enc_private_key = pow(generator, private_key, prime), private_key

    def generate_symmetric_key(self):
        self.symmetric_key = pow(self.peer_enc_public_key, self.my_enc_private_key, self.prime)

    def sign_public_key(self):
        # Convert public key to byte
        enc_public_key_bytes = self.my_enc_public_key.to_bytes(16, byteorder='big')
        signature = self.my_sign_private_key.sign(
            enc_public_key_bytes,
            padding.PSS(
                mgf=padding.MGF1(hashes.SHA256()),
                salt_length=padding.PSS.MAX_LENGTH
            ),
            hashes.SHA256()
        )

        return enc_public_key_bytes, signature
