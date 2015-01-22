require 'openssl'
require 'base64'

module Cryptonite
  class Coder # :nodoc:
    HEADER = "Cryptonite #{VERSION}: "
    BASE64_REGEXP = %r{([A-Za-z0-9+/]{4})*([A-Za-z0-9+/]{4}|[A-Za-z0-9+/]{3}=|[A-Za-z0-9+/]{2}==)}
    SEMVER_REGEXP = /
      \bv?(?:0|[1-9][0-9]*)\.(?:0|[1-9][0-9]*)\.
      (?:0|[1-9][0-9]*)(?:-[\da-z\-]+(?:\.[\da-z\-]+)*)?(?:\+[\da-z\-]+(?:\.[\da-z\-]+)*)?\b
    /ix
    REGEXP = /^Cryptonite #{SEMVER_REGEXP}: (?<value>#{BASE64_REGEXP})$/

    def initialize(key)
      fail ArgumentError unless key.is_a?(::OpenSSL::PKey::RSA)
      @key = key
    end

    # Encrypts a value with public key encryption. Keys should be defined in
    # environment.
    def encrypt(value)
      return unless value
      fail ArgumentError, 'Value is already encrypted' if value.match(REGEXP)
      HEADER + Base64.strict_encode64(@key.public_encrypt(value))
    end
    alias_method :dump, :encrypt

    # Decrypts a value with public key encryption. Keys should be defined in
    # environment.
    def decrypt(value)
      return unless value
      fail ArgumentError, 'Value is not encrypted' unless value.match(REGEXP)
      @key.private_decrypt(Base64.strict_decode64(Regexp.last_match(:value)))
    end
    alias_method :load, :decrypt
  end
end
