##
## client.py: Dropbox @ CSCI1660 (Spring 2021)
##
## This is the file where all of your code for your Dropbox client
## implementation must go.
##

## WARNING: You MUST NOT change these default imports. If you change the default
##          import statements in the stencil code, your implementation will be
##          rejected by the autograder. (Our autograder actually enforces this
##          this correctly, as opposed to the Crewmate Academy's autograder
##          from the Handin project!)

# Optional library containing some helpful string constants; not required to use
# this in your implementation. See https://docs.python.org/3/library/string.html
# for usage and documentation.
import string

# Imports the `crypto` and `util` libraries. See the Dropbox Wiki for usage and
# documentation.
import support.crypto as crypto
import support.util as util

# Imports the `dataserver`, `keyserver`, and `memloc` instances. See the Dropbox
# Wiki for usage and documentation.
from support.dataserver import dataserver, memloc
from support.keyserver import keyserver

# DO NOT EDIT ABOVE THIS LINE ##################################################

# Global Variables
SALT_LEN = 16       # 16 bytes salt length
KEY_LEN = 16        # 16 bytes is the symmetric key length

class User:
    def __init__(self, username, user_salt, user_pk, user_sk, user_symmetric_key, user_hmac) -> None:
        """
        Class constructor for the `User` class.

        You are free to add fields to the User class by changing the definition
        of this function.
        """
        self.username = username
        self.user_salt = user_salt
        self.user_pk = user_pk
        self.user_sk = user_sk
        self.user_symmetric_key = user_symmetric_key
        self.user_hmac = user_hmac

        # now that we have all the required info, we need to store the public key
        # and this above generated data inside the keyserver and the dataserver
        # create the python dictionary which will be stored on the data server
        user_data_dict = {
            'username': self.username,
            'hashed_password': crypto.Hash(self.user_salt + self.password),
            'user_sk_encrypted': crypto.SymmetricEncrypt(self.user_symmetric_key, crypto.SecureRandom(KEY_LEN), self.user_sk),
            'user_hmac': self.user_hmac,
        }
        # get a memloc from the username (so that we can consistently access this location)
        try:
            user_data_memloc = memloc.MakeFromBytes(bytes(self.username))
        except ValueError:
            raise util.DropboxError("input to MakeFromBytes is not 16 bytes in length.")
        # store the user_data_bytes in this memory location
        try:
            dataserver.Set(user_data_memloc, util.ObjectToBytes(user_data_dict))
        except ValueError:
            raise util.DropboxError("dataserver requires storage to be in bytes.")

        # Store the public key in the keyserver
        try:
            keyserver.Set(username, user_pk)
        except ValueError:
            raise util.DropboxError("user already has a corresponding public key in database. Cannot create same username.")


    def upload_file(self, filename: str, data: bytes) -> None:
        """
        The specification for this function is at:
        http://dropbox.crewmate.academy/client-api/storage/upload-file.html
        """
        # TODO: Implement!
        raise util.DropboxError("Not Implemented")

    def download_file(self, filename: str) -> bytes:
        """
        The specification for this function is at:
        http://dropbox.crewmate.academy/client-api/storage/download-file.html
        """
        # TODO: Implement!
        raise util.DropboxError("Not Implemented")

    def append_file(self, filename: str, data: bytes) -> None:
        """
        The specification for this function is at:
        http://dropbox.crewmate.academy/client-api/storage/append-file.html
        """
        # TODO: Implement!
        raise util.DropboxError("Not Implemented")

    def share_file(self, filename: str, recipient: str) -> None:
        """
        The specification for this function is at:
        http://dropbox.crewmate.academy/client-api/sharing/share-file.html
        """
        # TODO: Implement!
        raise util.DropboxError("Not Implemented")

    def receive_file(self, filename: str, sender: str) -> None:
        """
        The specification for this function is at:
        http://dropbox.crewmate.academy/client-api/sharing/receive-file.html
        """
        # TODO: Implement!
        raise util.DropboxError("Not Implemented")

    def revoke_file(self, filename: str, old_recipient: str) -> None:
        """
        The specification for this function is at:
        http://dropbox.crewmate.academy/client-api/sharing/revoke-file.html
        """
        # TODO: Implement!
        raise util.DropboxError("Not Implemented")

def create_user(username: str, password: str) -> User:
    """
    The specification for this function is at:
    http://dropbox.crewmate.academy/client-api/authentication/create-user.html
    """
    # STEP 1: Create a salt for the user
    user_salt = crypto.SecureRandom(SALT_LEN)
    # STEP 2: Generate a PK/SK pair
    user_pk, user_sk = crypto.AsymmetricKeyGen()
    # STEP 3: Generate a symmetric key for the user
    user_symmetric_key = crypto.PasswordKDF(password, user_salt, KEY_LEN)
    # STEP 4: Generate an HMAC for the (PW + SALT) + SK with the <user_symmetric_key>
    user_hmac = crypto.HMAC(user_symmetric_key, password + user_salt + user_sk)
    
    return User(username, user_salt, user_pk, user_sk, user_symmetric_key, user_hmac)

def authenticate_user(username: str, password: str) -> User:
    """
    The specification for this function is at:
    http://dropbox.crewmate.academy/client-api/authentication/authenticate-user.html
    """
    # TODO: Implement!
    raise util.DropboxError("Not Implemented")
