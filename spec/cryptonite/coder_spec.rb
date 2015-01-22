require 'spec_helper'

require 'cryptonite/coder'

describe Cryptonite::Coder do
  context 'with private key' do
    subject do
      Cryptonite::Coder.new(PRIVATE_FIXTURE_KEY)
    end

    it 'encrypts a value' do
      value = SecureRandom.hex(16)

      expect(subject.encrypt value).not_to eq(value)
    end

    it 'decrypts a value' do
      value = SecureRandom.hex(16)
      encrypted_value = Cryptonite::Coder::HEADER + Base64.strict_encode64(PUBLIC_FIXTURE_KEY.public_encrypt(value))

      expect(subject.decrypt encrypted_value).to eq(value)
    end

    it 'handles nil values' do
      expect(subject.encrypt nil).to be_nil
      expect(subject.decrypt nil).to be_nil
    end
  end

  context 'with public key only' do
    subject do
      Cryptonite::Coder.new(PUBLIC_FIXTURE_KEY)
    end

    it 'encrypts a value' do
      value = SecureRandom.hex(16)

      expect(subject.encrypt value).not_to eq(value)
    end

    it 'cannot decrypt a value' do
      value = SecureRandom.hex(16)
      encrypted_value = Cryptonite::Coder::HEADER + Base64.strict_encode64(PUBLIC_FIXTURE_KEY.public_encrypt(value))

      expect { subject.decrypt encrypted_value }.to raise_error(OpenSSL::PKey::RSAError)
    end

    it 'handles nil values' do
      expect(subject.encrypt nil).to be_nil
      expect(subject.decrypt nil).to be_nil
    end
  end
end
