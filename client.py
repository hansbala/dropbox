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
SALT_LEN = 16  # 16 bytes salt length
KEY_LEN = 16  # 16 bytes is the symmetric key length


class User:
    def __init__(self, username, key) -> None:
        """
        Class constructor for the `User` class.

        You are free to add fields to the User class by changing the definition
        of this function.
        """
        self.username = username
        self.user_key = key

    def upload_file(self, filename: str, data: bytes) -> None:
        """
        The specification for this function is at:
        http://dropbox.crewmate.academy/client-api/storage/upload-file.html
        """
        # generate a symmetric key for the file
        file_symmetric_key = crypto.SecureRandom(KEY_LEN)
        # create a memloc where the file data will be stored, encrypt, and store it
        file_data_memloc = memloc.Make()
        dataserver.Set(
            file_data_memloc,
            crypto.SymmetricEncrypt(file_symmetric_key,
                                    crypto.SecureRandom(KEY_LEN), data))
        # keep track of locations of all data memlocs associated with the file
        file_data_memlocs_list = [file_data_memloc]
        # keep track of all users associated with the file
        users = {
            "owner": self.username,
        }
        # create all needed memlocs
        memloc_file_data_memloc_lists = memloc.Make()
        memloc_users = memloc.Make()
        # store needed info in memlocs
        dataserver.Set(memloc_file_data_memloc_lists,
                       util.ObjectToBytes(file_data_memlocs_list))
        dataserver.Set(memloc_users, util.ObjectToBytes(users))

        # accumulate all this file metadata required
        file_metadata = {
            "symmetric_key": file_symmetric_key,
            "users": memloc_users,
            "data_locs": memloc_file_data_memloc_lists,
        }
        # generate a location to store this metadata from the combo of hash(filename + username)
        memloc_file_metadata = memloc.MakeFromBytes(
            crypto.Hash(util.ObjectToBytes(filename + self.username))[:16])
        # encrypt this file metadata and store it in the above location
        dataserver.Set(
            memloc_file_metadata,
            crypto.SymmetricEncrypt(self.user_key,
                                    crypto.SecureRandom(KEY_LEN),
                                    util.ObjectToBytes(file_metadata)))

    def download_file(self, filename: str) -> bytes:
        """
        The specification for this function is at:
        http://dropbox.crewmate.academy/client-api/storage/download-file.html
        """
        # get the file metadata location
        memloc_file_metadata = memloc.MakeFromBytes(
            crypto.Hash(util.ObjectToBytes(filename + self.username))[:16])
        # get the file metadata
        try:
            file_metadata = util.BytesToObject(
                crypto.SymmetricDecrypt(self.user_key,
                                        dataserver.Get(memloc_file_metadata)))
        except:
            raise util.DropboxError("Could not find file!")
        # get the file symmetric key
        file_symmetric_key = file_metadata["symmetric_key"]
        # iterate over all file data locations, decrypt and append to result, and then return the result
        result = bytes()
        for file_data_location in file_metadata["data_locs"]:
            result += crypto.SymmetricDecrypt(
                file_symmetric_key, dataserver.Get(file_data_location))
        return result

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
    # generate the memloc where the user data is stored
    user_memloc = memloc.MakeFromBytes(
        crypto.Hash(util.ObjectToBytes(username))[:16])

    # generate the pk, sk for the user
    user_pk, user_sk = crypto.AsymmetricKeyGen()
    # generate the salt for the user
    salt = crypto.SecureRandom(SALT_LEN)
    # generate the user symmetric key
    user_key = crypto.PasswordKDF(password, salt, KEY_LEN)
    # create the password hash
    pwd_salted_hash = crypto.Hash(util.ObjectToBytes(password) + salt)

    # create each of the memlocs
    memloc_sk = memloc.Make()
    memloc_salt = memloc.Make()
    memloc_pwd = memloc.Make()
    memloc_hmac = memloc.Make()

    # encrypt the user sk
    enc_user_sk = crypto.SymmetricEncrypt(user_key,
                                          crypto.SecureRandom(KEY_LEN),
                                          bytes(user_sk))
    # generate the hmac for the salted_pwd_hash + salt + enc_user_sk
    user_hmac = crypto.HMAC(user_key, pwd_salted_hash + salt + enc_user_sk)

    # store the public key in the keyserver
    try:
        keyserver.Set(username, user_pk)
    except:
        raise util.DropboxError(
            "Public key for user already exists. Cannot create user!")

    # store the necessary stuff in the memlocs
    dataserver.Set(memloc_sk, enc_user_sk)
    dataserver.Set(memloc_salt, salt)
    dataserver.Set(memloc_pwd, pwd_salted_hash)
    dataserver.Set(memloc_hmac, user_hmac)

    # create dictionary of all memlocs
    user_memlocs = {
        "password": memloc_pwd,
        "sk": memloc_sk,
        "salt": memloc_salt,
        "hmac": memloc_hmac,
    }
    # store this dictionary in the user_memloc created above
    dataserver.Set(user_memloc, util.ObjectToBytes(user_memlocs))
    return User(username, user_key)


def authenticate_user(username: str, password: str) -> User:
    """
    The specification for this function is at:
    http://dropbox.crewmate.academy/client-api/authentication/authenticate-user.html
    """
    # get the user memloc where it is stored
    user_memloc = memloc.MakeFromBytes(
        crypto.Hash(util.ObjectToBytes(username))[:16])
    # retrieve the user memlocs
    user_memlocs = util.BytesToObject(dataserver.Get(user_memloc))
    # retrieve the password hash
    server_pwd_salted_hash = dataserver.Get(user_memlocs.get("password"))
    # retrieve the salt
    server_salt = dataserver.Get(user_memlocs.get("salt"))
    # retrieve the encrypted private key
    enc_user_sk = dataserver.Get(user_memlocs.get("sk"))
    # retrieve the HMAC
    server_hmac = dataserver.Get(user_memlocs.get("hmac"))

    # generate the user symmetric key
    user_key = crypto.PasswordKDF(password, server_salt, KEY_LEN)

    # compute the HMAC
    hmac = crypto.HMAC(user_key,
                       server_pwd_salted_hash + server_salt + enc_user_sk)

    if not crypto.HMACEqual(hmac, server_hmac):
        raise util.DropboxError(
            "Cannot authenticate user. Data has been tampered with!")

    # compute the salted hash given the entered password
    pwd_salted_hash = crypto.Hash(util.ObjectToBytes(password) + server_salt)

    # check if they are equal
    if pwd_salted_hash == server_pwd_salted_hash:
        # generate the user
        return User(username, user_key)
    else:
        raise util.DropboxError("Could not authenticate user")
