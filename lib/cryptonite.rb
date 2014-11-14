require 'cryptonite/version'

require 'openssl'
require 'base64'

require 'active_support/concern'
require 'active_support/lazy_load_hooks'

# Cryptonite
#
# Enables the encryption of specific ActiveRecord attributes.
module Cryptonite
  extend ActiveSupport::Concern

  included do
    class_attribute :_attr_encrypted, instance_accessor: false
    self._attr_encrypted = []
  end

  module ClassMethods
    # Attributes listed as encrypted will be transparently encrypted and
    # decrypted in database operations.
    def attr_encrypted(*attributes)
      options = attributes.extract_options!

      @public_key = get_rsa_key(options[:public_key] || options[:key_pair] || ENV['PUBLIC_KEY'])
      @private_key = get_rsa_key(options[:private_key] || options[:key_pair] || ENV['PRIVATE_KEY'], options[:private_key_password] || ENV['PRIVATE_KEY_PASSWORD'])

      for attribute in attributes do
        serialize attribute, Coder.new(@private_key || @public_key)
      end

      self._attr_encrypted = Set.new(attributes.map { |a| a.to_s }) + (self._attr_encrypted || [])
    end

    # Returns an array of all the attributes that have been specified as encrypted.
    def encrypted_attributes
      self._attr_encrypted
    end

  private
    # Retrives an RSA key with multiple ways.
    def get_rsa_key(key, password = nil)
      return nil unless key

      if key.is_a?(Proc)
        key = key.call
      end

      if key.is_a?(Symbol)
        key = @instance.send(key)
      end

      return key if key.is_a?(::OpenSSL::PKey::RSA)

      if key.respond_to?(:read)
        key = key.read
      elsif key !~ /^-+BEGIN .* KEY-+$/
        key = File.read(key)
      end

      if password.nil?
        ::OpenSSL::PKey::RSA.new(key)
      else
        ::OpenSSL::PKey::RSA.new(key, password.to_s)
      end
    end
  end

  class Coder # :nodoc:
    def initialize(key)
      raise ArgumentError unless key.is_a?(::OpenSSL::PKey::RSA)
      @key = key
    end

    # Encrypts a value with public key encryption. Keys should be defined in
    # environment.
    def encrypt(value)
      Base64.encode64(@key.public_encrypt(value))
    end
    alias :dump :encrypt

    # Decrypts a value with public key encryption. Keys should be defined in
    # environment.
    def decrypt(value)
      @key.private_decrypt(Base64.decode64(value))
    end
    alias :load :decrypt
  end
end

ActiveSupport.on_load :active_record do
  include Cryptonite
end
