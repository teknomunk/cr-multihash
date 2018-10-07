require "varint"
require "digest/md5"
require "digest/sha1"
require "openssl"

# TODO: Write documentation for `Multihash`
module MultiHash
	VERSION = "0.1.0"

	class HashFunctionNotImplemented < Exception; end
	class DigestLengthError < Exception; end

	macro hash( name, code )
		{% 
			HASH_CODES[code] = name 
		%}
		{% ident = name.id.gsub(/-/,"_") %}
		{{ident.upcase}} = {{code}}
		def self.encode_{{ident}}( data )
			return encode( digest_{{ident}}( data ), "{{name.id}}" )
		end
	end

	HASH_CODES = {} of Int32 => String
	HASH_FUNCTIONS = {} of Int32 => Proc(Bytes,Bytes)
	hash "identity", 0x00
	hash "sha1", 0x11
	hash "sha2-256", 0x12
	hash "sha2-512", 0x13

# TODO: implement digest_* functions for the following:
#	hash "sha3-512", 0x14
#	hash "sha3-384", 0x15
#	hash "sha3-256", 0x16
#	hash "sha3-224", 0x17
#	hash "sha3", SHA3_512
#	hash "keccak-224", 0x1A
#	hash "keccak-156", 0x1B
#	hash "keccak-384", 0x1C
#	hash "keccak-512", 0x1D

#	hash "shake-128", 0x18
#	hash "shake-256", 0x19

#	hash "murmur3", 0x22
#	hash "murmur3-128", 0x22
#	hash "murmur3-32", 0x23

#	hash "dbl-sha2-256", 0x56

#	{% for i in 1...64 %}
#		hash {{"blake2b-#{ i * 8 }"}}, {{6401 + i}}
#	{% end %}
#	{% for i in 1...64 %}
#		hash {{"blake2s-#{ i * 8 }"}}, {{6465 + i}}
#	{% end %}

	#hash "md4", 0xD4
	#hash "md5", 0xD5

#	def self.digest_md5( data )
#		Digest::MD5.digest( data )
#	end

	def self.digest_identity( data )
		data
	end
	def self.digest_sha1( data ) : Bytes
		res = Bytes.new(20)
		Digest::SHA1.digest( data ).each_with_index {|b,i| res[i] = b.to_u8 }
		return res
	end
	def self.digest_sha2_256( data ) : Bytes
		h = OpenSSL::Digest.new("SHA256")
		h.update(data)
		h.digest
	end
	def self.digest_sha2_512( data ) : Bytes
		h = OpenSSL::Digest.new("SHA512")
		h.update(data)
		h.digest
	end
	def self.digest_sha3( data ) : Bytes
		self.digest_sha3_512(data)
	end

	def self.encode( digest, hash_function )
		code = HASH_CODES.key_for?(hash_function)
		hash_size = digest.size
		raise HashFunctionNotImplemented.new("unknown hash function #{hash_function}") if code.nil?

		io=IO::Memory.new
		io.write VarInt::MSB.encode_unsigned(code)
		io.write VarInt::MSB.encode_unsigned(hash_size)
		io.write digest.to_slice

		return io.to_slice
	end
	def self.decode( io : IO )
		code,bytes = VarInt::MSB.decode_unsigned(io)
		hash_size,bytes = VarInt::MSB.decode_unsigned(io)
		hash = Bytes.new( hash_size.to_i32, 0 )
		if io.read_fully?(hash).nil?
			raise DigestLengthError.new("Not enough bytes in source, expecting #{hash_size}") 
		end

		if !HASH_CODES.has_key?(code)
			raise HashFunctionNotImplemented.new( "Unable to find hash function for code #{code}" ) 
		end

		return {HASH_CODES[code],hash_size,hash}
	end
	def self.check( io : IO, data )
		type,size,hash = decode( io )
		
		{% begin %}
		case type
			# Add cases for every has that has a digest_* function
			{% for k,v in HASH_CODES %}
			when {{v}}
				return digest_{{v.gsub(/-/,"_").id}}( data )[0,size] == hash
			{% end %}

			# If the type is not available and if it hasn't already raised an error, do one now
			else
				raise HashFunctionNotImplemented.new("digest_#{type.gsub(/-/,"")} does not exist")
		end
		{% end %}
	end
end
