from dh_key import *


if __name__ == '__main__':
    alice_dh_key_ins = DhKey()
    # Alice send (trans, g^x) to Bob
    # transcript = (G, g, m)
    bob_dh_key_ins = DHkeyReceiver(alice_dh_key_ins.prime, alice_dh_key_ins.order, alice_dh_key_ins.generator, alice_dh_key_ins.my_enc_public_key)

    # Bob signs his public key with RSA
    bob_public_key_bytes, signature = bob_dh_key_ins.sign_public_key()

    # Alice verifies the signature
    if not alice_dh_key_ins.verify_public_key(bob_dh_key_ins.my_sign_public_key, signature, bob_public_key_bytes):
        print('Signature is incorrect, something went wrong!')
        exit(1)

    # Alice computes symmetric key using the message she got
    alice_dh_key_ins.generate_symmetric_key(int.from_bytes(bob_public_key_bytes, byteorder='big'))
    # Bob computes symmetric key. Bob already knew the public key of Alice
    bob_dh_key_ins.generate_symmetric_key()

    if alice_dh_key_ins.symmetric_key == bob_dh_key_ins.symmetric_key:
        print(f'symmetric_key {alice_dh_key_ins.symmetric_key} matched!!!!!')
    else:
        print(f'symmetric_key {alice_dh_key_ins.symmetric_key} did not match....')
        print(f'Alice has {alice_dh_key_ins.symmetric_key}\nBob has {bob_dh_key_ins.symmetric_key}')
