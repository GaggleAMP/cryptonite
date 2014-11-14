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
      create_table :sensitive_data, :force => true do |t|
        t.column :secret, :text
      end
    end
  end

  subject {
    Class.new(ActiveRecord::Base) do
      def self.table_name
        "sensitive_data"
      end    
    end
  }

  context "with both keys" do
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
        instance.instance_variable_get(:@attributes).send(:fetch, 'secret').value = Base64.encode64(PUBLIC_FIXTURE_KEY.public_encrypt(secret))

        expect(instance.secret).to eq(secret)
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

  context "with public key only" do
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
        instance.instance_variable_get(:@attributes).send(:fetch, 'secret').value = Base64.encode64(PUBLIC_FIXTURE_KEY.public_encrypt(secret))

        expect{ instance.secret }.to raise_error OpenSSL::PKey::RSAError
      end
    end
  end
end
