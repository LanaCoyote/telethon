import hashlib

AUTH_KEY_LENGTH = 2048//8
MSG_KEY_LENGTH  = 128//8
CLIENT_OFFSET   = 0
SERVER_OFFSET   = 8

class CryptoException( Exception ) :
    pass


def get_auth_key( ) :
    """
    Gets the user's locally stored auth key.

    NOTE: yet to be implemented :3
    """
    return b"0"*AUTH_KEY_LENGTH


def validate_key( key, length ) :
    """
    Validates that a given key is a bytes object of the given length. If
    it's not a bytes object, it converts it. If it's not of a valid length,
    it raises a CryptoException.

    params:
     - key: the key to validate
     - length: the length (in bytes) that the key should be equal to

    returns:
     - the key passed, as a byte array
    """

    if not isinstance( key, bytes ) :
        key = bytes( key )
    
    if len( key ) != length :
        raise CryptoException(
            "key is the wrong length to make AES keys (was {}, should be {})".format( len( key ), length )
        )

    return key


def authkeys_to_aeskeys( auth_key, msg_key, is_client = True ) :
    """
    Converts the authorization key and message key to the AES key and
    initialization vector used for encryption.

    See https://core.telegram.org/mtproto/description#defining-aes-key-and-initialization-vector for more information.

    params:
     - auth_key: 2048-bit authorization key
     - msg_key: 128-bit message key
     - is_client: True if we should use the client encryption protocol

    returns:
     - a tuple containing aes_key and aes_iv
    """

    # check that we've received valid data
    auth_key = validate_key( auth_key, AUTH_KEY_LENGTH )
    msg_key  = validate_key( msg_key, MSG_KEY_LENGTH )

    # set the offset based on which alg we're using (client or server)
    offset = CLIENT_OFFSET if is_client else SERVER_OFFSET

    # generate the sha1 keys
    sha1_a = hashlib.sha1(
        msg_key + auth_key[offset:offset + 32]
    ).digest()

    sha1_b = hashlib.sha1(
        auth_key[offset + 32:offset + 48] + msg_key + auth_key[offset + 48:offset + 64]
    ).digest()

    sha1_c = hashlib.sha1(
        auth_key[offset + 64:offset + 96] + msg_key
    ).digest()

    sha1_d = hashlib.sha1(
        msg_key + auth_key[96 + offset:128 + offset]
    ).digest()

    # generate our AES key and init vector
    aes_key = sha1_a[0:8]  + sha1_b[8:20] + sha1_c[4:16]
    aes_iv  = sha1_a[8:20] + sha1_b[0:8]  + sha1_c[16:20] + sha1_d[0:8]

    return ( aes_key, aes_iv )


def msgdata_to_msgkey( message ) :
    """
    Converts a message object into a SHA-1 hash (the msg_key)

    params:
     - message: the message object to hash
    
    returns:
     - a 128 bit msg_key hash
    """

    sha1 = hashlib.sha1( message ).digest()

    return sha1[len(sha1)-128//8:]
