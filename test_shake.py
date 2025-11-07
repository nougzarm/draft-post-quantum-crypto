from Crypto.Hash import SHAKE128

data = b"Ceci est un test pour SHAKE128"

shake = SHAKE128.new()
shake.update(data)

output_32 = shake.read(32)

output_next_32 = shake.read(32)

print(f"32 premiers octets  : {output_32.hex()}")
print(f"32 octets suivants : {output_next_32.hex()}")