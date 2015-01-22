module Cryptonite
  module KeyExtractor # :nodoc:
    private

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
end
