import click
import json
import base64
import ecdsa
import sys
from pathlib import Path
from lib import pre
from lib.key_manager import KeyManager


@click.command("gen-cc")
@click.option("--output", default="cc.json", help="Path to save the crypto context.")
@click.option("--plaintext-modulus", default=65537, type=int, help="Plaintext modulus.")
@click.option("--scaling-mod-size", default=60, type=int, help="Scaling modulus size.")
def gen_cc(output, plaintext_modulus, scaling_mod_size):
    """Generates crypto context."""
    click.echo("Generating crypto context...", err=True)
    cc = pre.create_crypto_context(
        plaintext_modulus=plaintext_modulus, scaling_mod_size=scaling_mod_size
    )
    serialized_cc = pre.serialize(cc)

    with open(output, "w") as f:
        json.dump({"cc": serialized_cc}, f)

    click.echo(f"Crypto context saved to {output}", err=True)


@click.command("gen-signing-keys")
@click.option(
    "--output-prefix", default="idk_signing", help="Prefix for the output key files."
)
def gen_signing_keys(output_prefix):
    """Generates a classic ECDSA key pair for signing."""
    click.echo("Generating ECDSA signing key pair...", err=True)

    sk, pk_hex = KeyManager.generate_classic_keypair()

    pk_path = f"{output_prefix}.pub"
    sk_path = f"{output_prefix}.sec"

    with open(pk_path, "w") as f:
        f.write(pk_hex)

    with open(sk_path, "w") as f:
        f.write(sk.to_string().hex())

    click.echo(f"Signing public key saved to {pk_path}", err=True)
    click.echo(f"Signing secret key saved to {sk_path}", err=True)


@click.command("gen-keys")
@click.option("--cc-path", default="cc.json", help="Path to the crypto context file.")
@click.option("--output-prefix", default="key", help="Prefix for the output key files.")
def gen_keys(cc_path, output_prefix):
    """Generates a public/private key pair."""
    click.echo(f"Loading crypto context from {cc_path}...", err=True)
    with open(cc_path, "r") as f:
        cc_data = json.load(f)

    cc = pre.deserialize_cc(base64.b64decode(cc_data["cc"]))

    click.echo("Generating keys...", err=True)
    keys = pre.generate_keys(cc)

    serialized_pk = pre.serialize(keys.publicKey)
    serialized_sk = pre.serialize(keys.secretKey)

    pk_path = f"{output_prefix}.pub"
    sk_path = f"{output_prefix}.sec"

    with open(pk_path, "w") as f:
        json.dump({"key": serialized_pk}, f)

    with open(sk_path, "w") as f:
        json.dump({"key": serialized_sk}, f)

    click.echo(f"Public key saved to {pk_path}", err=True)
    click.echo(f"Secret key saved to {sk_path}", err=True)


@click.command()
@click.option("--cc-path", default="cc.json", help="Path to the crypto context file.")
@click.option("--pk-path", help="Path to the public key file.", required=True)
@click.option(
    "--signing-key-path",
    help="Path to the ECDSA private key for signing message headers.",
    required=True,
)
@click.option("--data", help="String to encrypt.")
@click.option(
    "--input-file",
    type=click.Path(exists=True, dir_okay=False),
    help="Path to a file to encrypt.",
)
@click.option(
    "--output", default="ciphertext.idk", help="Path to save the IDK message file."
)
def encrypt(cc_path, pk_path, signing_key_path, data, input_file, output):
    """Encrypts data and packages it into a spec-compliant IDK message."""
    if not data and not input_file:
        raise click.UsageError("Either --data or --input-file must be provided.")
    if data and input_file:
        raise click.UsageError("Provide either --data or --input-file, not both.")

    # Dynamic import to avoid circular dependency if idk_message needs cli elements
    from lib import idk_message

    click.echo(f"Loading crypto context from {cc_path}...", err=True)
    with open(cc_path, "r") as f:
        cc_data = json.load(f)
    cc = pre.deserialize_cc(base64.b64decode(cc_data["cc"]))

    click.echo(f"Loading public key from {pk_path}...", err=True)
    with open(pk_path, "r") as f:
        pk_data = json.load(f)
    pk = pre.deserialize_public_key(base64.b64decode(pk_data["key"]))

    click.echo(f"Loading signing key from {signing_key_path}...", err=True)
    with open(signing_key_path, "r") as f:
        sk_hex = f.read()
        sk_sign = ecdsa.SigningKey.from_string(
            bytes.fromhex(sk_hex), curve=ecdsa.SECP256k1
        )

    if input_file:
        with open(input_file, "rb") as f:
            input_data_bytes = f.read()
    else:
        input_data_bytes = data.encode("utf-8")

    click.echo("Encrypting data and creating IDK message parts...", err=True)
    message_parts = idk_message.create_idk_message_parts(
        data=input_data_bytes,
        cc=cc,
        pk=pk,
        signing_key=sk_sign,
    )

    with open(output, "w") as f:
        f.write("\n".join(message_parts))

    click.echo(f"IDK message saved to {output}", err=True)


@click.command()
@click.option("--cc-path", default="cc.json", help="Path to the crypto context file.")
@click.option("--sk-path", help="Path to the secret key file.", required=True)
@click.option(
    "--verifying-key-path",
    help="Path to the ECDSA public key for verifying message signatures.",
    required=True,
)
@click.option(
    "--ciphertext-path", default="ciphertext.idk", help="Path to the IDK message file."
)
@click.option(
    "--output-file",
    type=click.Path(dir_okay=False),
    help="Path to save the decrypted output.",
)
def decrypt(cc_path, sk_path, verifying_key_path, ciphertext_path, output_file):
    """Parses, verifies, and decrypts a spec-compliant IDK message."""
    from lib import idk_message

    click.echo(f"Loading crypto context from {cc_path}...", err=True)
    with open(cc_path, "r") as f:
        cc_data = json.load(f)
    cc = pre.deserialize_cc(base64.b64decode(cc_data["cc"]))

    click.echo(f"Loading secret key from {sk_path}...", err=True)
    with open(sk_path, "r") as f:
        sk_data = json.load(f)
    sk = pre.deserialize_secret_key(base64.b64decode(sk_data["key"]))

    click.echo(f"Loading verifying key from {verifying_key_path}...", err=True)
    with open(verifying_key_path, "r") as f:
        vk_hex = f.read()
        vk_verify = ecdsa.VerifyingKey.from_string(
            bytes.fromhex(vk_hex), curve=ecdsa.SECP256k1
        )

    click.echo(f"Loading IDK message from {ciphertext_path}...", err=True)
    with open(ciphertext_path, "r") as f:
        message_content = f.read()

    # Decrypt and write to output
    try:
        decrypted_data = idk_message.decrypt_idk_message(
            cc=cc, sk=sk, message_str=message_content
        )
        Path(output_file).write_bytes(decrypted_data)
        click.echo(f"Success! Decrypted data written to {output_file}", err=True)
    except Exception as e:
        click.echo(f"Error during decryption: {e}", err=True)
        sys.exit(1)


@click.command("gen-rekey")
@click.option("--cc-path", default="cc.json", help="Path to the crypto context file.")
@click.option(
    "--sk-path-from",
    help="Path to the secret key file of the 'from' party (e.g., Alice).",
    required=True,
)
@click.option(
    "--pk-path-to",
    help="Path to the public key file of the 'to' party (e.g., Bob).",
    required=True,
)
@click.option(
    "--output", default="rekey.json", help="Path to save the re-encryption key."
)
def gen_rekey(cc_path, sk_path_from, pk_path_to, output):
    """Generates a re-encryption key."""
    click.echo(f"Loading crypto context from {cc_path}...", err=True)
    with open(cc_path, "r") as f:
        cc_data = json.load(f)
    cc = pre.deserialize_cc(base64.b64decode(cc_data["cc"]))

    click.echo(f"Loading 'from' secret key from {sk_path_from}...", err=True)
    with open(sk_path_from, "r") as f:
        sk_data = json.load(f)
    sk_from = pre.deserialize_secret_key(base64.b64decode(sk_data["key"]))

    click.echo(f"Loading 'to' public key from {pk_path_to}...", err=True)
    with open(pk_path_to, "r") as f:
        pk_data = json.load(f)
    pk_to = pre.deserialize_public_key(base64.b64decode(pk_data["key"]))

    click.echo("Generating re-encryption key...", err=True)
    rekey = pre.generate_re_encryption_key(cc, sk_from, pk_to)
    serialized_rekey = pre.serialize(rekey)

    with open(output, "w") as f:
        json.dump({"rekey": serialized_rekey}, f)

    click.echo(f"Re-encryption key saved to {output}", err=True)


@click.command("re-encrypt")
@click.option("--cc-path", default="cc.json", help="Path to the crypto context file.")
@click.option(
    "--rekey-path", default="rekey.json", help="Path to the re-encryption key file."
)
@click.option(
    "--ciphertext-path", help="Path to the original ciphertext file.", required=True
)
@click.option(
    "--output",
    default="reciphertext.json",
    help="Path to save the re-encrypted ciphertext.",
)
def re_encrypt(cc_path, rekey_path, ciphertext_path, output):
    """Re-encrypts a ciphertext."""
    click.echo(f"Loading crypto context from {cc_path}...", err=True)
    with open(cc_path, "r") as f:
        cc_data = json.load(f)
    cc = pre.deserialize_cc(base64.b64decode(cc_data["cc"]))

    click.echo(f"Loading re-encryption key from {rekey_path}...", err=True)
    with open(rekey_path, "r") as f:
        rekey_data = json.load(f)
    rekey = pre.deserialize_re_encryption_key(base64.b64decode(rekey_data["rekey"]))

    click.echo(f"Loading ciphertext from {ciphertext_path}...", err=True)
    with open(ciphertext_path, "r") as f:
        ciphertext_data = json.load(f)

    length = ciphertext_data.get("length")

    if "ciphertexts" not in ciphertext_data:
        raise click.ClickException(
            "Invalid or legacy ciphertext format. Re-encryption requires a JSON file "
            "with a 'ciphertexts' key. The IDK message format is not supported."
        )

    serialized_items = ciphertext_data["ciphertexts"]
    ciphertexts = [pre.deserialize_ciphertext(s_item) for s_item in serialized_items]

    click.echo("Re-encrypting ciphertext...", err=True)
    re_ciphertexts = pre.re_encrypt(cc, rekey, ciphertexts)
    serialized_re_ciphertexts = [pre.serialize(ct) for ct in re_ciphertexts]

    output_data = {"ciphertexts": serialized_re_ciphertexts}
    if length is not None:
        output_data["length"] = length

    with open(output, "w") as f:
        json.dump(output_data, f)

    click.echo(f"Re-encrypted ciphertext saved to {output}", err=True)
