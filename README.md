# Cryptonite

This gem enables the encryption of specific ActiveRecord attributes using
public key encryption. The advantage is that write only operations do not
require the presence of the private key and thus front-end machines will not
expose encrypted data in the event of a security breach.

Of course you are as safe as your encryption algorithm and key, so no
guarantees there. Moreover, this library acts as a front-end to OpenSSL API of
the Ruby standard library, which handles the encryption, and should not be
considered as cryptography software.

## Installation

Add this line to your application's Gemfile:

    gem 'cryptonite'

And then execute:

    $ bundle

## Usage

Cryptonite adds to ActiveRecord the `attr_encrypted` method, which is used to declare
the attributes that will be transparently encrypted, e.g.

    attr_encrypted :secret, :another_secret

The library operates by serializing the fields with a custom encoder that will
do encryption / decryption of the attribute value.

In order to encrypt the data the library should be provided with the public key
path, and respectively in order to decrypt them it requires the private key
path along with its password. Those settings can be set either in the
environment, using the variable names `PUBLIC_KEY`, `PRIVATE_KEY` and
`PRIVATE_KEY_PASSWORD`, or be passed as options to the `attr_encrypted` method:

    attr_encrypted :secret, public_key: File.read('public_key.pem')
    attr_encrypted :another_secret, private_key: 'private_key.pem', private_key_password: 'test'
    attr_encrypted :yet_another_secret, key_pair: :get_key_method

If an application does not need to retrieve the encrypted information it is not
required for the private key settings to be defined. Moreover, please note that
ActiveRecord methods that operate massively on records do not use the
serialization features and so encryption / decryption does not take place
there. This is by design.

## Key Generation

Generate a key pair:

```shell
openssl genrsa -des3 -out private.pem 2048
Generating RSA private key, 2048 bit long modulus
......+++
.+++
e is 65537 (0x10001)
Enter pass phrase for private.pem:
Verifying - Enter pass phrase for private.pem:
```

and extract the the public key:

```shell
openssl rsa -in private.pem -out public.pem -outform PEM -pubout
Enter pass phrase for private.pem:
writing RSA key
```

## Contributing

1. Fork it ( https://github.com/GaggleAMP/cryptonite/fork )
2. Create your feature branch (`git checkout -b my-new-feature`)
3. Commit your changes (`git commit -am 'Add some feature'`)
4. Push to the branch (`git push origin my-new-feature`)
5. Create a new Pull Request
