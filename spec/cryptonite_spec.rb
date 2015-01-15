require 'spec_helper'

require 'cryptonite'

require 'active_record'

describe Cryptonite do
  before do
    ::ActiveRecord::Base.establish_connection(adapter: 'sqlite3',
                                              encoding: 'utf8',
                                              reconnect: false,
                                              database: ':memory:')

    ::ActiveRecord::Schema.define do
      create_table :sensitive_data, force: true do |t|
        t.column :secret, :text
      end
    end
  end

  subject do
    Class.new(ActiveRecord::Base) do
      def self.table_name
        'sensitive_data'
      end
    end
  end

  context 'with private key' do
    before do
      subject.tap { |obj| obj.attr_encrypted :secret, key_pair: PRIVATE_FIXTURE_KEY }
    end

    it 'encrypts field in database' do
      secret = SecureRandom.hex(16)

      subject.new(secret: secret).tap do |instance|
        expect(
          instance.instance_variable_get(:@attributes).send(:fetch, 'secret').serialized_value
        ).not_to eq(secret)
      end
    end

    it 'decrypts field in database' do
      secret = SecureRandom.hex(16)

      subject.new.tap do |instance|
        instance.instance_variable_get(:@attributes).send(:fetch, 'secret').value =
          Cryptonite::TOKEN + Base64.encode64(PUBLIC_FIXTURE_KEY.public_encrypt(secret))

        expect(instance.secret).to eq(secret)
      end
    end

    it 'handles nil values' do
      subject.new(secret: nil).tap do |instance|
        expect(
          instance.instance_variable_get(:@attributes).send(:fetch, 'secret').serialized_value
        ).to be_nil
      end

      subject.new.tap do |instance|
        instance.instance_variable_get(:@attributes).send(:fetch, 'secret').value = nil

        expect(instance.secret).to be_nil
      end
    end

    it 'encrypts and decrypts field in database' do
      secret = SecureRandom.hex(16)

      subject.create(secret: secret).reload.tap do |instance|
        expect(
          instance.instance_variable_get(:@attributes).send(:fetch, 'secret').serialized_value
        ).not_to eq(secret)

        expect(instance.secret).to eq(secret)
      end
    end
  end

  context 'with public key only' do
    before do
      subject.tap { |obj| obj.attr_encrypted :secret, public_key: PUBLIC_FIXTURE_KEY }
    end

    it 'encrypts field in database' do
      secret = SecureRandom.hex(16)

      subject.new(secret: secret).tap do |instance|
        expect(
          instance.instance_variable_get(:@attributes).send(:fetch, 'secret').serialized_value
        ).not_to eq(secret)
      end
    end

    it 'cannot decrypt field in database' do
      secret = SecureRandom.hex(16)

      subject.new.tap do |instance|
        instance.instance_variable_get(:@attributes).send(:fetch, 'secret').value =
          Cryptonite::TOKEN + Base64.encode64(PUBLIC_FIXTURE_KEY.public_encrypt(secret))

        expect { instance.secret }.to raise_error OpenSSL::PKey::RSAError
      end
    end

    it 'handles nil values' do
      subject.new(secret: nil).tap do |instance|
        expect(
          instance.instance_variable_get(:@attributes).send(:fetch, 'secret').serialized_value
        ).to be_nil
      end

      subject.new.tap do |instance|
        instance.instance_variable_get(:@attributes).send(:fetch, 'secret').value = nil

        expect(instance.secret).to be_nil
      end
    end
  end

  context 'during upwards migration' do
    before do
      @secret = SecureRandom.hex(16)
      subject.create(secret: @secret)

      subject.tap { |obj| obj.attr_encrypted :secret, key_pair: PRIVATE_FIXTURE_KEY }
    end

    it 'encrypts field in database' do
      expect(subject.last.instance_variable_get(:@attributes).send(:fetch, 'secret').value).to eq(@secret)

      Cryptonite.encrypt_model_attributes(subject, :secret, key_pair: PRIVATE_FIXTURE_KEY)

      expect(subject.last.instance_variable_get(:@attributes).send(:fetch, 'secret').unserialized_value).to eq(@secret)
    end
  end

  context 'during downwards migration' do
    before do
      subject.tap { |obj| obj.attr_encrypted :secret, key_pair: PRIVATE_FIXTURE_KEY }

      @secret = SecureRandom.hex(16)
      subject.create(secret: @secret)
    end

    it 'decrypts field in database' do
      expect(subject.last.instance_variable_get(:@attributes).send(:fetch, 'secret').unserialized_value).to eq(@secret)

      Cryptonite.decrypt_model_attributes(subject, :secret, key_pair: PRIVATE_FIXTURE_KEY)

      expect(subject.last.instance_variable_get(:@attributes).send(:fetch, 'secret').value).to eq(@secret)
    end
  end
end
