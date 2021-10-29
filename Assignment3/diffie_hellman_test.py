import unittest

from elliptic_curve_diffie_hellman import *

class TestDiffieHellman(unittest.TestCase):
    def test_simple(self):
        a = ECDH()
        b = ECDH()
        a_pub = a.get_public_key()
        b_pub = b.get_public_key()
        self.assertEqual(a.get_shared_key(b_pub), b.get_shared_key(a_pub))

if __name__ == '__main__':
    unittest.main()