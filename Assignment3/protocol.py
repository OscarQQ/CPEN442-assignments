import json
from elliptic_curve_diffie_hellman import *
from cipher import *
from enum import IntEnum
from random import randrange
import sys

class User(IntEnum):
    CLIENT = 0
    SERVER = 1
class Protocol:
    # Initializer (Called from app.py)
    # TODO: MODIFY ARGUMENTS AND LOGIC AS YOU SEEM FIT
    def __init__(self):
        self.ecdh = ECDH()
        pass


    # Creating the initial message of your protocol (to be send to the other party to bootstrap the protocol)
    # TODO: IMPLEMENT THE LOGIC (MODIFY THE INPUT ARGUMENTS AS YOU SEEM FIT)
    def GetProtocolInitiationMessage(self):
        self._my_nounce = randrange(sys.maxsize)
        # Declare the other side's idetity whom send the request to
        self._other_id = User.CLIENT if self._id == User.SERVER else User.SERVER
        msg = {
            'id': self._id,
            'nounce': self._my_nounce
        }
        return json.dumps(msg)


    # Checking if a received message is part of your protocol (called from app.py)
    # TODO: IMPLMENET THE LOGIC
    def IsMessagePartOfProtocol(self, message):
        try:
            json.loads(message) # If a message is a Json string, it must be an auth message. Because encrypted message cannot be in Json format 
        except json.decoder.JSONDecodeError:
            return False
        return True

    # Processing protocol message
    # TODO: IMPLMENET THE LOGIC (CALL SetSessionKey ONCE YOU HAVE THE KEY ESTABLISHED)
    # THROW EXCEPTION IF AUTHENTICATION FAILS
    def ProcessReceivedProtocolMessage(self, message):
        previous_step = self.VerifyAuthenticationStep(message)
        msg = json.loads(message)

        shared_key = ''
        return_message = ''
        if previous_step == 0:
            self._other_nounce = msg['nounce']
            self._other_id = msg['id']

            # Verify the other side by checking identity. Only SERVER and CLIENT are allowed to send request to each other. 
            if (self._id == User.SERVER and self._other_id != User.CLIENT) or (self._id == User.CLIENT and self._other_id != User.SERVER):
                raise Exception('Authentication failed veryfying identity after step 0')

            self._my_nounce = randrange(sys.maxsize)
            message_to_encrypt = {
               'id': self._id,
               'your_nounce': self._other_nounce,
               'public_key': str(self.ecdh.get_public_key())
            }

            return_message = json.dumps({
                'nounce': self._my_nounce,
                'encrypted_message': str(self.EncryptAndProtectMessage(json.dumps(message_to_encrypt)))
            })

        elif previous_step == 1:
            self._other_nounce = msg['nounce']
            encrypted_message = msg['encrypted_message']
            decrypted_message = json.loads(self.DecryptAndVerifyMessage(encrypted_message))
            decrypted_nounce = decrypted_message['your_nounce']
            other_id = decrypted_message['id']

            # Verify the other side by checking returned nounce
            if self._my_nounce != decrypted_nounce:
                raise Exception('Authentication failed veryfying nounce after step 1')

            # Verify the other side by checking identity. Encrypted id has to be identical to the id declared before sending message 0
            if other_id != self._other_id:
                print(f'Other id: {self._other_id}. Received other id: {other_id}')
                raise Exception('Authentication failed veryfying identity after step 1')

            # Passed 1-way authentication here
            other_public_key = decrypted_message['public_key']
            shared_key = self.ecdh.get_shared_key(other_public_key)

            message_to_encrypt = {
               'id': self._id,
               'your_nounce': self._other_nounce,
               'public_key': str(self.ecdh.get_public_key())
            }
            return_message = json.dumps({
                'encrypted_message': str(self.EncryptAndProtectMessage(json.dumps(message_to_encrypt)))
            })
            
        elif previous_step == 2:
            encrypted_message = msg['encrypted_message']
            decrypted_message = json.loads(self.DecryptAndVerifyMessage(encrypted_message))
            decrypted_nounce = decrypted_message['your_nounce']
            other_id = decrypted_message['id']


            # Verify the other side by checking returned nounce
            if self._my_nounce != decrypted_nounce:
                raise Exception('Authentication failed veryfying nounce at step 2')
            
            # Verify the other side by checking identity. Encrypted id has to be identical to the id provided at step 0.
            if other_id != self._other_id:
                raise Exception('Authentication failed veryfying identity after step 2')

            # Passed mutual authentication here
            other_public_key = decrypted_message['public_key']
            shared_key = self.ecdh.get_shared_key(other_public_key)
            
        else:
            raise Exception('Authentication failed!')
        
        return shared_key, return_message
    
    # Check and verity which step that a auth message belongs to
    def VerifyAuthenticationStep(self, message):
        msg = json.loads(message)

        if 'id' in msg and 'nounce' in msg:
            return 0
        if 'nounce' in msg and 'encrypted_message' in msg:
            return 1
        if 'encrypted_message' in msg:
            return 2
        
        raise Exception('Authentication failed! Invalid authentication message')


    # Setting the key for the current session
    # TODO: MODIFY AS YOU SEEM FIT
    def SetSessionKey(self, key):
        self._key = str(key)
        print(f"My very secret key is {self._key}")
        pass


    # Encrypting messages
    # TODO: IMPLEMENT ENCRYPTION WITH THE SESSION KEY (ALSO INCLUDE ANY NECESSARY INFO IN THE ENCRYPTED MESSAGE FOR INTEGRITY PROTECTION)
    # RETURN AN ERROR MESSAGE IF INTEGRITY VERITIFCATION OR AUTHENTICATION FAILS
    def EncryptAndProtectMessage(self, plain_text):
        return Cipher.encrypt(plain_text, self._key)


    # Decrypting and verifying messages
    # TODO: IMPLEMENT DECRYPTION AND INTEGRITY CHECK WITH THE SESSION KEY
    # RETURN AN ERROR MESSAGE IF INTEGRITY VERITIFCATION OR AUTHENTICATION FAILS
    def DecryptAndVerifyMessage(self, cipher_text):
        return Cipher.decrypt(cipher_text, self._key)
