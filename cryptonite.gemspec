# coding: utf-8
lib = File.expand_path('../lib', __FILE__)
$LOAD_PATH.unshift(lib) unless $LOAD_PATH.include?(lib)
require 'cryptonite/version'

Gem::Specification.new do |spec|
  spec.name          = 'cryptonite'
  spec.version       = Cryptonite::VERSION
  spec.authors       = ['GaggleAMP']
  spec.email         = ['info@gaggleamp.com']
  spec.summary       = 'Enables the encryption of specific ActiveRecord attributes.'
  spec.description   = 'Enables the encryption of specific ActiveRecord attributes.'
  spec.homepage      = 'https://github.com/GaggleAMP/cryptonite'
  spec.license       = 'MIT'

  spec.files         = `git ls-files -z`.split("\x0")
  spec.executables   = spec.files.grep(/^bin\//) { |f| File.basename(f) }
  spec.test_files    = spec.files.grep(/^(test|spec|features)\//)
  spec.require_paths = ['lib']

  spec.add_development_dependency 'bundler', '~> 1.6'
  spec.add_development_dependency 'rake'
  spec.add_development_dependency 'rspec', '~> 3.1'
  spec.add_development_dependency 'sqlite3'
  spec.add_development_dependency 'rubocop'
  spec.add_dependency 'activerecord',  '>= 4.0', '< 4.2'
  spec.add_dependency 'activesupport', '>= 4.0', '< 4.2'
end
