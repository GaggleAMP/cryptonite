require 'bolt/version'

require 'openssl'
require 'base64'

require 'active_support/concern'
require 'active_support/lazy_load_hooks'

# Bolt
#
# Enables the encryption of specific ActiveRecord attributes.
module Bolt
  extend ActiveSupport::Concern

  PUBLIC_KEY = OpenSSL::PKey::RSA.new(File.read(ENV['PUBLIC_KEY_FILE'])) rescue nil
  PRIVATE_KEY = OpenSSL::PKey::RSA.new(File.read(ENV['PRIVATE_KEY_FILE']), ENV['PRIVATE_KEY_PASSWORD']) rescue nil

  included do
    class_attribute :_attr_encrypted, instance_accessor: false
    self._attr_encrypted = []
  end

  module ClassMethods
    # Attributes listed as encrypted will be transparently encrypted and
    # decrypted in database operations.
    def attr_encrypted(*attributes)
      self._attr_encrypted = Set.new(attributes.map { |a| a.to_s }) + (self._attr_encrypted || [])
    end

    # Returns an array of all the attributes that have been specified as encrypted.
    def encrypted_attributes
      self._attr_encrypted
    end
  end

  # Wrap write_attribute to encrypt value.
  def write_attribute(attr_name, value)
    attr_name = attr_name.to_s

    if self.class.encrypted_attributes.include?(attr_name)
      value = encrypt(value)
    end unless value.nil?

    super(attr_name, value)
  end

  # Wrap read_attribute to encrypt value.
  def read_attribute(attr_name)
    attr_name = attr_name.to_s

    if self.class.encrypted_attributes.include?(attr_name)
      value = super(attr_name)
      decrypt(value) unless value.nil?
    else
      super(attr_name)
    end
  end

  private
    # Encrypts a value with public key encryption. Keys should be defined in
    # environment.
    def encrypt(value)
      raise ActiveRecord::ActiveRecordError.new("Undefined public key for encrypted attribute") if PUBLIC_KEY.nil?

      Base64.encode64(PUBLIC_KEY.public_encrypt(value))
    end

    # Decrypts a value with public key encryption. Keys should be defined in
    # environment.
    def decrypt(value)
      raise ActiveRecord::ActiveRecordError.new("Undefined private key for encrypted attribute") if PRIVATE_KEY.nil?

      PRIVATE_KEY.private_decrypt(Base64.decode64(value))
    end
end

ActiveSupport.on_load :active_record do
  include Bolt
end
