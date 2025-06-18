import click
from lib import pre
import json


@click.group()
def cli():
    """A CLI tool for demonstrating proxy re-encryption."""
    pass


@cli.command("gen-cc")
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


@cli.command("gen-keys")
@click.option("--cc-path", default="cc.json", help="Path to the crypto context file.")
@click.option("--output-prefix", default="key", help="Prefix for the output key files.")
def gen_keys(cc_path, output_prefix):
    """Generates a public/private key pair."""
    click.echo(f"Loading crypto context from {cc_path}...", err=True)
    with open(cc_path, "r") as f:
        cc_data = json.load(f)

    cc = pre.deserialize_cc(cc_data["cc"])

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


@cli.command()
@click.option("--cc-path", default="cc.json", help="Path to the crypto context file.")
@click.option("--pk-path", help="Path to the public key file.", required=True)
@click.option("--data", help="Comma-separated list of integers to encrypt.")
@click.option(
    "--input-file",
    type=click.Path(exists=True, dir_okay=False),
    help="Path to a file to encrypt.",
)
@click.option(
    "--output", default="ciphertext.json", help="Path to save the ciphertext."
)
def encrypt(cc_path, pk_path, data, input_file, output):
    """Encrypts data with a public key."""
    if not data and not input_file:
        raise click.UsageError("Either --data or --input-file must be provided.")
    if data and input_file:
        raise click.UsageError("Provide either --data or --input-file, not both.")

    click.echo(f"Loading crypto context from {cc_path}...", err=True)
    with open(cc_path, "r") as f:
        cc_data = json.load(f)
    cc = pre.deserialize_cc(cc_data["cc"])

    click.echo(f"Loading public key from {pk_path}...", err=True)
    with open(pk_path, "r") as f:
        pk_data = json.load(f)
    pk = pre.deserialize_public_key(pk_data["key"])

    if input_file:
        with open(input_file, "rb") as f:
            input_data = list(f.read())
    else:
        try:
            input_data = [int(x.strip()) for x in data.split(",")]
        except ValueError:
            click.echo(
                "Error: Data must be a comma-separated list of integers.", err=True
            )
            return

    click.echo("Encrypting data...", err=True)
    ciphertext = pre.encrypt(cc, pk, input_data)
    serialized_ciphertext = pre.serialize(ciphertext)

    with open(output, "w") as f:
        json.dump({"length": len(input_data), "ciphertext": serialized_ciphertext}, f)

    click.echo(f"Ciphertext saved to {output}", err=True)


@cli.command()
@click.option("--cc-path", default="cc.json", help="Path to the crypto context file.")
@click.option("--sk-path", help="Path to the secret key file.", required=True)
@click.option(
    "--ciphertext-path", default="ciphertext.json", help="Path to the ciphertext file."
)
@click.option(
    "--output-file",
    type=click.Path(dir_okay=False),
    help="Path to save the decrypted output.",
)
def decrypt(cc_path, sk_path, ciphertext_path, output_file):
    """Decrypts data with a secret key."""
    click.echo(f"Loading crypto context from {cc_path}...", err=True)
    with open(cc_path, "r") as f:
        cc_data = json.load(f)
    cc = pre.deserialize_cc(cc_data["cc"])

    click.echo(f"Loading secret key from {sk_path}...", err=True)
    with open(sk_path, "r") as f:
        sk_data = json.load(f)
    sk = pre.deserialize_secret_key(sk_data["key"])

    click.echo(f"Loading ciphertext from {ciphertext_path}...", err=True)
    with open(ciphertext_path, "r") as f:
        ciphertext_data = json.load(f)
    ciphertext = pre.deserialize_ciphertext(ciphertext_data["ciphertext"])
    length = ciphertext_data.get("length")

    click.echo("Decrypting data...", err=True)
    decrypted_data = pre.decrypt(cc, sk, ciphertext, length)

    if output_file:
        with open(output_file, "wb") as f:
            f.write(bytes(decrypted_data))
        click.echo(f"Decrypted data written to {output_file}", err=True)
    else:
        click.echo(f"{decrypted_data}")


@cli.command("gen-rekey")
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
    cc = pre.deserialize_cc(cc_data["cc"])

    click.echo(f"Loading 'from' secret key from {sk_path_from}...", err=True)
    with open(sk_path_from, "r") as f:
        sk_data = json.load(f)
    sk_from = pre.deserialize_secret_key(sk_data["key"])

    click.echo(f"Loading 'to' public key from {pk_path_to}...", err=True)
    with open(pk_path_to, "r") as f:
        pk_data = json.load(f)
    pk_to = pre.deserialize_public_key(pk_data["key"])

    click.echo("Generating re-encryption key...", err=True)
    rekey = pre.generate_re_encryption_key(cc, sk_from, pk_to)
    serialized_rekey = pre.serialize(rekey)

    with open(output, "w") as f:
        json.dump({"rekey": serialized_rekey}, f)

    click.echo(f"Re-encryption key saved to {output}", err=True)


@cli.command("re-encrypt")
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
    cc = pre.deserialize_cc(cc_data["cc"])

    click.echo(f"Loading re-encryption key from {rekey_path}...", err=True)
    with open(rekey_path, "r") as f:
        rekey_data = json.load(f)
    rekey = pre.deserialize_re_encryption_key(rekey_data["rekey"])

    click.echo(f"Loading ciphertext from {ciphertext_path}...", err=True)
    with open(ciphertext_path, "r") as f:
        ciphertext_data = json.load(f)
    ciphertext = pre.deserialize_ciphertext(ciphertext_data["ciphertext"])
    length = ciphertext_data.get("length")

    click.echo("Re-encrypting ciphertext...", err=True)
    re_ciphertext = pre.re_encrypt(cc, rekey, ciphertext)
    serialized_re_ciphertext = pre.serialize(re_ciphertext)

    output_data = {"ciphertext": serialized_re_ciphertext}
    if length is not None:
        output_data["length"] = length

    with open(output, "w") as f:
        json.dump(output_data, f)

    click.echo(f"Re-encrypted ciphertext saved to {output}", err=True)


if __name__ == "__main__":
    cli()
