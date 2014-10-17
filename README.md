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

The library operates by overriding `read_attribute` and `write_attribute`
methods, intercepting with the encryption / decryption of the attribute value.

In order to encrypt the data the library should be provided with the public key
path, and respectively in order to decrypt them it requires the private key
path along with its password. Currently, those settings are set only in the
environment, using the variable names `PUBLIC_KEY_FILE`, `PRIVATE_KEY_FILE` and
`PRIVATE_KEY_PASSWORD`.

If an application does not need to retrieve the encrypted information it is not
required for the private key settings to be defined. However, please note that
during development the `inspect` method does call the `read_attribute` method
and hence it will fail if a private key is not provided.

Moreover, please note that ActiveRecord methods that operate massively on
records do not use the `read_attribute` and `write_attribute` methods and so
encryption / decryption does not take place there. This is by design.

## Contributing

1. Fork it ( https://github.com/GaggleAMP/cryptonite/fork )
2. Create your feature branch (`git checkout -b my-new-feature`)
3. Commit your changes (`git commit -am 'Add some feature'`)
4. Push to the branch (`git push origin my-new-feature`)
5. Create a new Pull Request
