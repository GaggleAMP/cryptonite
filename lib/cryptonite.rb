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

      public_key = extract_public_key(options)
      private_key = extract_private_key(options)

      serialize_attributes_with_coder(attributes, private_key || public_key)

      self._attr_encrypted = Set.new(attributes.map(&:to_s)) + (_attr_encrypted || [])
    end

    # Returns an array of all the attributes that have been specified as encrypted.
    def encrypted_attributes
      _attr_encrypted
    end

    private

    # Serializes all attributes with encryption coder.
    def serialize_attributes_with_coder(attributes, key)
      attributes.each do |attribute|
        serialize attribute, Coder.new(key)
      end
    end

    # Extracts public key from options or the environment.
    def extract_public_key(options)
      extract_key(options[:public_key] || options[:key_pair] || ENV['PUBLIC_KEY'])
    end

    # Extracts private key from options or the environment.
    def extract_private_key(options)
      extract_key(
        options[:private_key] || options[:key_pair] || ENV['PRIVATE_KEY'],
        options[:private_key_password] || ENV['PRIVATE_KEY_PASSWORD']
      )
    end

    # Retrives an RSA key with multiple ways.
    def extract_key(key, password = nil)
      return nil unless key

      case key
      when Proc then extract_key_from_proc(key, password)
      when Symbol then extract_key_from_method(key, password)
      when ::OpenSSL::PKey::RSA then key
      else
        key = retrieve_key_string_from_stream(key)
        return ::OpenSSL::PKey::RSA.new(key) if password.nil?
        ::OpenSSL::PKey::RSA.new(key, password.to_s)
      end
    end

    # Retrives an RSA key with a `proc` block.
    def extract_key_from_proc(proc, password = nil)
      extract_key(proc.call, password)
    end

    # Retrives an RSA key with a method symbol.
    def extract_key_from_method(method, password = nil)
      extract_key(@instance.send(method), password)
    end

    # Retrives a key string from a stream.
    def retrieve_key_string_from_stream(stream)
      return stream.read if stream.respond_to?(:read)
      return File.read(stream) if stream.to_s !~ /^-+BEGIN .* KEY-+$/
      stream
    end
  end

  class Coder # :nodoc:
    def initialize(key)
      fail ArgumentError unless key.is_a?(::OpenSSL::PKey::RSA)
      @key = key
    end

    # Encrypts a value with public key encryption. Keys should be defined in
    # environment.
    def encrypt(value)
      Base64.encode64(@key.public_encrypt(value)) if value
    end
    alias_method :dump, :encrypt

    # Decrypts a value with public key encryption. Keys should be defined in
    # environment.
    def decrypt(value)
      @key.private_decrypt(Base64.decode64(value)) if value
    end
    alias_method :load, :decrypt
  end
end

ActiveSupport.on_load :active_record do
  include Cryptonite
end
