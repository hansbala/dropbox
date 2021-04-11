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
    def __init__(self, username, key, sk) -> None:
        """
        Class constructor for the `User` class.

        You are free to add fields to the User class by changing the definition
        of this function.
        """
        self.username = username
        self.user_key = key
        self.sk = sk

    def does_data_exist(self, memloc: bytes) -> bool:
        try:
            dataserver.Get(memloc)
            return True
        except:
            return False

    def file_exists(self, filename: str) -> bool:
        memloc_file_metadata_ptr = memloc.MakeFromBytes(
            crypto.Hash(util.ObjectToBytes(filename + self.username))[:16])
        try:
            dataserver.Get(memloc_file_metadata_ptr)
            return True
        except:
            return False
    
    def update_file(self, filename: str, data: bytes) -> None:
        # get the file metadata location
        memloc_file_metadata_ptr = memloc.MakeFromBytes(
            crypto.Hash(util.ObjectToBytes(filename + self.username))[:16])
        memloc_file_metadata = dataserver.Get(memloc_file_metadata_ptr)
        
        # get the file's symmetric key
        file_key_memloc = memloc.MakeFromBytes(crypto.Hash(util.ObjectToBytes(filename + self.username + 'key'))[:16])

        # get the file metadata
        try:
            file_key_encrypted = dataserver.Get(file_key_memloc)
            file_key = crypto.AsymmetricDecrypt(self.sk, file_key_encrypted)
            file_metadata = util.BytesToObject(
                crypto.SymmetricDecrypt(file_key,
                                        dataserver.Get(memloc_file_metadata)))
        except:
            raise util.DropboxError("Could not find file!")

        #get list of memlocs to append new memloc to
        file_locations_memloc = file_metadata["data_locs"]
        loc = dataserver.Get(file_locations_memloc)
        file_locations = util.BytesToObject(loc)

        new_append_data = memloc.Make()
        dataserver.Set(new_append_data, crypto.SymmetricEncrypt(file_key,
          crypto.SecureRandom(KEY_LEN), data))
        
        file_locations = [new_append_data]
        dataserver.Set(file_locations_memloc, util.ObjectToBytes(file_locations))


    def upload_file(self, filename: str, data: bytes) -> None:
        """
        The specification for this function is at:
        http://dropbox.crewmate.academy/client-api/storage/upload-file.html
        """
        if self.file_exists(filename):
            self.update_file(filename, data)
            return
        # new file needs to be created
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
            # "symmetric_key": file_symmetric_key,
            "users": memloc_users,
            "data_locs": memloc_file_data_memloc_lists,
        }
        # generate a location to store this metadata
        memloc_file_metadata = memloc.Make()
        # generate a location to store this metadata from the combo of hash(filename + username)
        memloc_file_metadata_ptr = memloc.MakeFromBytes(
            crypto.Hash(util.ObjectToBytes(filename + self.username))[:16])
        dataserver.Set(
            memloc_file_metadata,
            crypto.SymmetricEncrypt(file_symmetric_key,
                                    crypto.SecureRandom(KEY_LEN),
                                    util.ObjectToBytes(file_metadata)))
        # store the pointer to the memloc_file_metadata
        dataserver.Set(memloc_file_metadata_ptr, memloc_file_metadata)

        
        # drop the symmetric key of the file in hash(filename + current user + 'key')
        file_key_memloc = memloc.MakeFromBytes(crypto.Hash(util.ObjectToBytes(filename + self.username + 'key'))[:16])
        user_public_key = keyserver.Get(self.username)
        file_key_encrypted = crypto.AsymmetricEncrypt(user_public_key, file_symmetric_key)
        # store this in the memloc
        dataserver.Set(file_key_memloc, file_key_encrypted)

    def download_file(self, filename: str) -> bytes:
        """
        The specification for this function is at:
        http://dropbox.crewmate.academy/client-api/storage/download-file.html
        """
        # get the file metadata location
        memloc_file_metadata_ptr = memloc.MakeFromBytes(
            crypto.Hash(util.ObjectToBytes(filename + self.username))[:16])
        try:
            memloc_file_metadata = dataserver.Get(memloc_file_metadata_ptr)
        except:
            raise util.DropboxError("Could not find file metadata memloc")
        # get the file's symmetric key
        file_key_memloc = memloc.MakeFromBytes(crypto.Hash(util.ObjectToBytes(filename + self.username + 'key'))[:16])
        try:
            try:
                file_key_encrypted = dataserver.Get(file_key_memloc)
                file_key = crypto.AsymmetricDecrypt(self.sk, file_key_encrypted)
            except:
                raise util.DropboxError("cannot find file key")
            # get the file metadata
            file_metadata_enc = dataserver.Get(memloc_file_metadata)
            file_metadata = util.BytesToObject(crypto.SymmetricDecrypt(file_key, file_metadata_enc))
        except:
            raise util.DropboxError("Could not find file metadata")
        # iterate over all file data locations, decrypt and append to result, and then return the result
        result = bytes()
        file_locations_memloc = file_metadata["data_locs"]
        file_locations = util.BytesToObject(dataserver.Get(file_locations_memloc))
        for file_data_location in file_locations:
            result += crypto.SymmetricDecrypt(
                file_key, dataserver.Get(file_data_location))
        return result

    def append_file(self, filename: str, data: bytes) -> None:
        """
        The specification for this function is at:
        http://dropbox.crewmate.academy/client-api/storage/append-file.html
        """
        # get the file metadata location
        memloc_file_metadata_ptr = memloc.MakeFromBytes(
            crypto.Hash(util.ObjectToBytes(filename + self.username))[:16])
        memloc_file_metadata = dataserver.Get(memloc_file_metadata_ptr)
        
        # get the file's symmetric key
        file_key_memloc = memloc.MakeFromBytes(crypto.Hash(util.ObjectToBytes(filename + self.username + 'key'))[:16])

        # get the file metadata
        try:
            file_key_encrypted = dataserver.Get(file_key_memloc)
            file_key = crypto.AsymmetricDecrypt(self.sk, file_key_encrypted)
            file_metadata = util.BytesToObject(
                crypto.SymmetricDecrypt(file_key,
                                        dataserver.Get(memloc_file_metadata)))
        except:
            raise util.DropboxError("Could not find file!")

        #get list of memlocs to append new memloc to
        file_locations_memloc = file_metadata["data_locs"]
        loc = dataserver.Get(file_locations_memloc)
        file_locations = util.BytesToObject(loc)

        new_append_data = memloc.Make()
        dataserver.Set(new_append_data, crypto.SymmetricEncrypt(file_key,
          crypto.SecureRandom(KEY_LEN), data))
        
        file_locations.append(new_append_data)
        dataserver.Set(file_locations_memloc, util.ObjectToBytes(file_locations))

    def share_file(self, filename: str, recipient: str) -> None:
        """
        The specification for this function is at:
        http://dropbox.crewmate.academy/client-api/sharing/share-file.html
        """
        try:
            # get the file's symmetric key
            file_key_memloc = memloc.MakeFromBytes(crypto.Hash(util.ObjectToBytes(filename + self.username + 'key'))[:16])
            file_key_encrypted = dataserver.Get(file_key_memloc)
            file_key = crypto.AsymmetricDecrypt(self.sk, file_key_encrypted)
        except:
            raise util.DropboxError("Could not find file key")
        
        # drop this key in hash(filename + sender + recipient + 'key')
        key_drop_memloc = memloc.MakeFromBytes(crypto.Hash(util.ObjectToBytes(filename + self.username + recipient + 'key'))[:16])
        # get the public key of the recipient
        recipient_pk = keyserver.Get(recipient)
        # encrypt the key with the public key of the user
        file_symmetric_key_encrypted = crypto.AsymmetricEncrypt(recipient_pk, file_key)
        # copy the key into this memloc
        dataserver.Set(key_drop_memloc, file_symmetric_key_encrypted)

        # drop the location of the file metadata in hash(filename + sender + recipient + 'location')
        file_metadata_location_memloc = memloc.MakeFromBytes(crypto.Hash(util.ObjectToBytes(filename + self.username + recipient + 'location'))[:16])
        # get the file metadata location
        drop_payload_loc = memloc.MakeFromBytes(crypto.Hash(util.ObjectToBytes(filename + self.username))[:16])
        try:
            drop_payload = dataserver.Get(drop_payload_loc)
        except:
            raise util.DropboxError("Could not find file metadata memloc")
        # copy pointer of memloc to required drop location
        dataserver.Set(file_metadata_location_memloc, drop_payload)

    def receive_file(self, filename: str, sender: str) -> None:
        """
        The specification for this function is at:
        http://dropbox.crewmate.academy/client-api/sharing/receive-file.html
        """
        # get the memloc where the key was dropped
        key_drop_memloc = memloc.MakeFromBytes(crypto.Hash(util.ObjectToBytes(filename + sender + self.username + 'key'))[:16])
        # get the key
        try:
            file_key_encrypted = dataserver.Get(key_drop_memloc)
        except:
            raise util.DropboxError("Could not get shared file key from drop location")
        file_key = crypto.AsymmetricDecrypt(self.sk, file_key_encrypted)
        
        # get the memloc where the memloc of the file metadata was dropped
        file_metadata_location_memloc = memloc.MakeFromBytes(crypto.Hash(util.ObjectToBytes(filename + sender + self.username + 'location'))[:16])
        try:
            file_metadata_memloc = dataserver.Get(file_metadata_location_memloc)
        except:
            raise util.DropboxError("Could not get memloc of file metadata location")
        
        # generate the place where we can place the key and the memloc of the file metadata location
        memloc_file_metadata_ptr = memloc.MakeFromBytes(
            crypto.Hash(util.ObjectToBytes(filename + self.username))[:16])
        file_key_memloc = memloc.MakeFromBytes(crypto.Hash(util.ObjectToBytes(filename + self.username + 'key'))[:16])
        # check if something exists at required locations
        if self.does_data_exist(memloc_file_metadata_ptr) or self.does_data_exist(file_key_memloc):
            raise util.DropboxError("Filename already exists for current user")
        else:
            # copy over the data to these memory locations
            dataserver.Set(memloc_file_metadata_ptr, file_metadata_memloc)
            dataserver.Set(file_key_memloc, file_key_encrypted)
        
        # now using file key, we must add ourselves as a user inside users, and then re-encrypt with the
        # file key
        try:
            file_metadata = util.BytesToObject(crypto.SymmetricDecrypt(file_key, dataserver.Get(file_metadata_memloc)))
        except:
            raise util.DropboxError("Could not find file metadata")
        user_memloc = file_metadata["users"]
        users = util.BytesToObject(dataserver.Get(user_memloc))
        data_locs = file_metadata["data_locs"]
        # now add current user to this dictionary in only one place (array of sender)
        if sender not in users:
            users[sender] = [self.username]
        else:
            users[sender].append(self.username)
        # update the users memloc to hold the new users stuff
        dataserver.Set(user_memloc, util.ObjectToBytes(users))
        new_file_metadata = {
            "users": user_memloc,
            "data_locs": data_locs,
        }
        encrypted_file_metadata = crypto.SymmetricEncrypt(file_key, crypto.SecureRandom(KEY_LEN), util.ObjectToBytes(new_file_metadata))
        # store this new metadata in the same location
        dataserver.Set(file_metadata_memloc, encrypted_file_metadata)

    def revoke_file(self, filename: str, old_recipient: str) -> None:
        """
        The specification for this function is at:
        http://dropbox.crewmate.academy/client-api/sharing/revoke-file.html
        """
        try:
            # get the file's symmetric key
            file_key_memloc = memloc.MakeFromBytes(crypto.Hash(util.ObjectToBytes(filename + self.username + 'key'))[:16])
            file_key_encrypted = dataserver.Get(file_key_memloc)
            file_key = crypto.AsymmetricDecrypt(self.sk, file_key_encrypted)
        except:
            raise util.DropboxError("Could not find file key")
        # get the pointer to file metadata location
        memloc_file_metadata_ptr = memloc.MakeFromBytes(crypto.Hash(util.ObjectToBytes(filename + self.username))[:16])
        try:
            file_metadata_memloc = dataserver.Get(memloc_file_metadata_ptr)
            file_metadata = util.BytesToObject(crypto.SymmetricDecrypt(file_key, dataserver.Get(file_metadata_memloc)))
        except:
            raise util.DropboxError("Could not find file metadata")

        # generate new key and distribute to remainder of the users
        new_file_key = crypto.SecureRandom(KEY_LEN)

        users_memloc = file_metadata["users"]
        users = util.BytesToObject(dataserver.Get(users_memloc))
        # update users dictionary here
        users_new = self.removeUserRecursive(users, old_recipient)
        # update the users_memloc with the new data
        dataserver.Set(users_memloc, util.ObjectToBytes(users_new))

        # get the data_locs memloc
        data_locs_memloc = file_metadata["data_locs"]
        data_locs = util.BytesToObject(dataserver.Get(data_locs_memloc))
        # TODO BUG: reencrypt data with new key
        for data_loc in data_locs:
            actual_data = crypto.SymmetricDecrypt(file_key, dataserver.Get(data_loc))
            new_encrypted_data = crypto.SymmetricEncrypt(new_file_key, crypto.SecureRandom(KEY_LEN), actual_data)
            # set the new data in this memloc
            dataserver.Set(data_loc, new_encrypted_data)

        # generate new file metadata payload
        new_file_metadata = {
            "users": users_memloc,
            "data_locs": data_locs_memloc
        }
        # re-encrypt the file metadata here and store it in memloc
        dataserver.Set(file_metadata_memloc, crypto.SymmetricEncrypt(new_file_key, crypto.SecureRandom(KEY_LEN), util.ObjectToBytes(new_file_metadata)))

        for key in users_new:
            if key == "owner": continue
            self.distributeKeys(users_new[key], new_file_key, filename)
        # distribute the key for the owner
        self.distributeKeys([users_new["owner"]], new_file_key, filename)

    def distributeKeys(self, users, new_file_key, filename) -> None:
        for user in users:
            new_file_key_drop_location = memloc.MakeFromBytes(crypto.Hash(util.ObjectToBytes(filename + user + 'key'))[:16])
            # get the public key
            user_pk = keyserver.Get(user)
            # encrypt the new key with the public key
            new_file_key_encrypted = crypto.AsymmetricEncrypt(user_pk, new_file_key)
            # copy over encrypted file to memloc
            dataserver.Set(new_file_key_drop_location, new_file_key_encrypted)
        
    def removeUserRecursive(self, users, old_recipient):
        for key in users:
            # deleting old_recip share 
            if old_recipient in users[key]:
                users[key].remove(old_recipient)
            # deleting other users old_recip shared with
            if key == old_recipient:
                for sub_old_recipient in list(users[old_recipient]):
                    self.removeUserRecursive(users, sub_old_recipient)

        users = {k: v for k, v in users.items() if v != []}
        return users


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
    return User(username, user_key, user_sk)


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

    # decrypt the secret key
    user_sk = crypto.SymmetricDecrypt(user_key, enc_user_sk)

    # compute the salted hash given the entered password
    pwd_salted_hash = crypto.Hash(util.ObjectToBytes(password) + server_salt)

    # check if they are equal
    if not pwd_salted_hash == server_pwd_salted_hash:
        raise util.DropboxError("Could not authenticate user")

    # compute the HMAC
    hmac = crypto.HMAC(user_key,
                       server_pwd_salted_hash + server_salt + enc_user_sk)

    if crypto.HMACEqual(hmac, server_hmac):
        # generate the user
        return User(username, user_key, user_sk)
    else:
        raise util.DropboxError(
            "Cannot authenticate user. Data has been tampered with!")

