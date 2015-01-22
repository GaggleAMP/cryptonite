require 'cryptonite/version'

require 'cryptonite/coder'
require 'cryptonite/key_extractor'

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
    include Cryptonite::KeyExtractor

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
  end

  module_function

  # Encrypts attributes of a specific model. This method is indended for migration purposes. It takes the same arguments
  # as the `attr_encrypted` class method.
  def encrypt_model_attributes(model, *attributes) # rubocop:disable Metrics/MethodLength, Metrics/AbcSize
    fail ArgumentError, "ActiveRecord::Base expected, got #{model.inspect}" unless model <= ActiveRecord::Base

    options = attributes.extract_options!
    encrypted_attributes = attributes.map(&:to_s) & model.column_names
    coder = Coder.new extract_public_key(options)

    model.find_each do |record|
      updated_columns =
        encrypted_attributes.each_with_object({}) do |attribute, values|
          values[attribute] = coder.encrypt(record.typecasted_attribute_value attribute)
        end

      record.update_columns(updated_columns)
    end
  end

  # Decrypts attributes of a specific model. This method is indended for migration purposes. It takes the same arguments
  # as the `attr_encrypted` class method. It requires a private key to decrypt the data.
  def decrypt_model_attributes(model, *attributes) # rubocop:disable Metrics/MethodLength, Metrics/AbcSize
    fail ArgumentError, "ActiveRecord::Base expected, got #{model.inspect}" unless model <= ActiveRecord::Base

    options = attributes.extract_options!
    encrypted_attributes = attributes.map(&:to_s) & model.column_names
    coder = Coder.new extract_private_key(options)

    model.find_each do |record|
      updated_columns =
        encrypted_attributes.each_with_object({}) do |attribute, values|
          values[attribute] = coder.decrypt(record.read_attribute_before_type_cast attribute)
        end

      record.update_columns(updated_columns)
    end
  end

  extend KeyExtractor
end

ActiveSupport.on_load :active_record do
  include Cryptonite
end
