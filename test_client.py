##
## test_client.py: Dropbox @ CSCI1660 (Spring 2021)
##
## This is the file where all of your test cases for your Dropbox client
## implementation must go.
##

## WARNING: You MUST NOT change these default imports. If you change the default
##          import statements in the stencil code, your implementation will be
##          rejected by the autograder. (Our autograder actually enforces this
##          this correctly, as opposed to the Crewmate Academy's autograder
##          from the Handin project!)

import unittest
import string

import support.crypto as crypto
import support.util as util

from support.dataserver import dataserver, memloc
from support.keyserver import keyserver

from client import create_user, authenticate_user, User

# DO NOT EDIT ABOVE THIS LINE ##################################################

class ClientTests(unittest.TestCase):
    def setUp(self):
        """
        This function is automatically called before every test is run. It
        clears the dataserver and keyserver to a clean state for each test case.
        """
        dataserver.Clear()
        keyserver.Clear()

    def test_create_user(self):
        """
        Checks user creation.
        """
        u = create_user("usr", "pswd")
        u2 = authenticate_user("usr", "pswd")

        self.assertEqual(vars(u), vars(u2))

    def test_upload(self):
        """
        Tests if uploading a file throws any errors.
        """
        u = create_user("usr", "pswd")
        u.upload_file("file1", b'testing data')

    def test_download(self):
        """
        Tests if a downloaded file has the correct data in it.
        """
        u = create_user("usr", "pswd")

        data_to_be_uploaded = b'testing data'

        u.upload_file("file1", data_to_be_uploaded)
        downloaded_data = u.download_file("file1")

        self.assertEqual(downloaded_data, data_to_be_uploaded)

    def test_share_and_download(self):
        """
        Simple test of sharing and downloading a shared file.
        """
        u1 = create_user("usr1", "pswd")
        u2 = create_user("usr2", "pswd")

        u1.upload_file("shared_file", b'shared data')
        u1.share_file("shared_file", "usr2")

        u2.receive_file("shared_file", "usr1")
        down_data = u2.download_file("shared_file")

        self.assertEqual(down_data, b'shared data')

    def test_download_error(self):
        """
        Simple test that tests that downloading a file that doesn't exist
        raise an error.
        """
        u = create_user("usr", "pswd")

        # NOTE: When using `assertRaises`, the code that is expected to raise an
        #       error needs to be passed to `assertRaises` as a lambda function.
        self.assertRaises(util.DropboxError, lambda: u.download_file("file1"))

    def test_the_next_test(self):
        """
        Implement more tests by defining more functions like this one!

        Functions have to start with the word "test" to be recognized. Refer to
        the Python `unittest` API for more information on how to write test
        cases: https://docs.python.org/3/library/unittest.html
        """
        self.assertTrue(True)

    
    def test_append_and_download_file_(self):
        """
        Simple test that tests that append_file works the way that it is supposed to.
        This test also tests multiple appends
        """

        u = create_user("usr", "pswd")

        data_to_be_uploaded = b'testing data'
        u.upload_file("file1", data_to_be_uploaded)

        data_to_be_appended = b' test'
        u.append_file("file1", data_to_be_appended)

        data_to_be_appended2 = b' test1'
        u.append_file("file1", data_to_be_appended2)

        data_to_be_appended3 = b' test2'
        u.append_file("file1", data_to_be_appended3)
        downloaded_data = u.download_file("file1")

        self.assertEqual(downloaded_data, b'testing data test test1 test2')
    
    def test_remove_user_recursive_1(self):
        u = create_user("test", "test")
        users = {
            "owner": "bob",
            "bob": ["tim", "hans", "minion1", "minion2"],
            "tim": ["alice", "yoda", "chungi"],
            "chungi": ["ross", "minji"],
            "minji": ["yanker", "rachel"],
            "rachel": ["boss1", "boss2", "joey"],
            "hans": ["ugly1", "ugly2"]
        }
        result = u.removeUserRecursive(users, "minji")
        self.assertEqual(True, True)

        # print(result)

    def test_revoke_file(self):
        bob = create_user("bob", "123")
        alice = create_user("alice", "123")
        zach = create_user("zach", "123")
        
        bob.upload_file('test', b'This is a test')
        bob.share_file('test', 'alice')
        alice.receive_file('test', 'bob')
        alice.share_file('test', 'zach')
        zach.receive_file('test', 'alice')

        bob.revoke_file('test', 'alice')

        self.assertRaises(util.DropboxError, lambda: alice.download_file('test'))
        self.assertRaises(util.DropboxError, lambda: zach.download_file('test'))




# DO NOT EDIT BELOW THIS LINE ##################################################

if __name__ == '__main__':
    unittest.main()
