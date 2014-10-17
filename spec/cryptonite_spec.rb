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
    end.tap { |obj| obj.attr_encrypted :secret }
  }

  context "with public key only" do
    before do
      stub_const('Cryptonite::PRIVATE_KEY', nil)
    end

    it 'encrypts field in database' do
      secret = SecureRandom.hex(16)

      subject.new(secret: secret).tap do |instance|
        expect(
          instance.instance_variable_get(:@attributes).send(:fetch, 'secret')
        ).not_to eq(secret)
      end
    end
  end

  context "with private key only" do
    before do
      stub_const('Cryptonite::PUBLIC_KEY', nil)
    end

    it 'decrypts field in database' do
      secret = SecureRandom.hex(16)

      subject.new.tap do |instance|
        instance.instance_variable_get(:@attributes).send(:store, 'secret', Base64.encode64(PUBLIC_FIXTURE_KEY.public_encrypt(secret)))

        expect(instance.secret).to eq(secret)
      end
    end
  end
end
