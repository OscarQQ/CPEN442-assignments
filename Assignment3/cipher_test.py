import unittest

from cipher import *

class TestCipher(unittest.TestCase):
    def test_simple(self):
        plaintext = "123"
        key = "blah blah"
        ciphertext = Cipher.encrypt(plaintext, key)
        decoded_plaintext = Cipher.decrypt(ciphertext, key).decode("utf-8")
        self.assertEqual(plaintext, decoded_plaintext)

if __name__ == '__main__':
    unittest.main()