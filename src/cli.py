import click
from lib import pre
import json
import requests
import hashlib
import os
from base64 import b64decode
import re
from pathlib import Path
import ecdsa
import base64
import sys


API_BASE_URL = os.environ.get("API_BASE_URL", "http://127.0.0.1:8000")


def get_nonce(api_url):
    """Helper to get a nonce from the API server."""
    try:
        nonce_resp = requests.get(f"{api_url}/nonce")
        nonce_resp.raise_for_status()
        return nonce_resp.json()["nonce"]
    except (requests.exceptions.RequestException, KeyError) as e:
        raise click.ClickException(f"Failed to get nonce from API: {e}")


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
@click.option(
    "--pieces-per-part",
    default=1,
    type=int,
    help="Number of ciphertext pieces per message part.",
)
def encrypt(
    cc_path, pk_path, signing_key_path, data, input_file, output, pieces_per_part
):
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
    cc = pre.deserialize_cc(cc_data["cc"])

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
        pieces_per_part=pieces_per_part,
    )

    with open(output, "w") as f:
        f.write("\n\n".join(message_parts))

    click.echo(f"IDK message saved to {output}", err=True)


@cli.command()
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
    cc = pre.deserialize_cc(cc_data["cc"])

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
            cc=cc, sk=sk, vk=vk_verify, message_str=message_content
        )
        Path(output_file).write_bytes(decrypted_data)
        click.echo(f"Success! Decrypted data written to {output_file}", err=True)
    except Exception as e:
        click.echo(f"Error during decryption: {e}", err=True)
        sys.exit(1)


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


@cli.command("upload")
@click.option("--pk-path", type=str, required=True)
@click.option("--auth-keys-path", type=click.Path(exists=True), required=True)
@click.option("--file-path", type=click.Path(exists=True), required=True)
@click.option(
    "--api-url",
    envvar="DCY_API_URL",
    default="https://api.dcypher.io",
    help="API base URL.",
)
def upload(pk_path, auth_keys_path, file_path, api_url):
    """Uploads a file to the remote storage API."""
    from lib import idk_message
    from lib.auth import sign_message_with_keys

    with open(file_path, "rb") as f:
        file_content = f.read()

    try:
        parsed_part = idk_message.parse_idk_message_part(file_content.decode("utf-8"))
        file_hash = parsed_part["headers"]["MerkleRoot"]
    except Exception as e:
        raise click.ClickException(f"Error parsing IDK message to get MerkleRoot: {e}")

    click.echo(f"Starting upload for file hash: {file_hash}...", err=True)
    nonce = get_nonce(api_url)

    try:
        auth_keys_data = json.loads(Path(auth_keys_path).read_text())
        classic_sk = ecdsa.SigningKey.from_string(
            bytes.fromhex(Path(auth_keys_data["classic_sk_path"]).read_text()),
            curve=ecdsa.SECP256k1,
        )
        pq_keys = []
        for pq_key_info in auth_keys_data["pq_keys"]:
            pq_keys.append(
                {
                    "sk": Path(pq_key_info["sk_path"]).read_bytes(),
                    "pk_hex": pq_key_info["pk_hex"],
                    "alg": pq_key_info["alg"],
                }
            )
    except Exception as e:
        raise click.ClickException(f"Error loading auth keys: {e}")

    message = f"UPLOAD:{pk_path}:{file_hash}:{nonce}".encode("utf-8")
    signatures = sign_message_with_keys(
        message, {"classic_sk": classic_sk, "pq_keys": pq_keys}
    )

    url = f"{api_url}/storage/{pk_path}"
    try:
        files = {"file": (file_hash, file_content, "application/octet-stream")}
        data = {
            "nonce": nonce,
            "file_hash": file_hash,
            "classic_signature": signatures["classic_signature"],
            "pq_signatures": json.dumps(signatures["pq_signatures"]),
        }
        response = requests.post(url, files=files, data=data)
        response.raise_for_status()
        click.echo("Upload successful.", err=True)
        click.echo(json.dumps(response.json(), indent=2))
    except requests.exceptions.RequestException as e:
        error_text = e.response.text if e.response else str(e)
        raise click.ClickException(f"API request failed: {error_text}")


@cli.command("download")
@click.option("--pk-path", type=str, required=True)
@click.option("--auth-keys-path", type=click.Path(exists=True), required=True)
@click.option("--file-hash", type=str, required=True)
@click.option(
    "--output-path",
    type=click.Path(dir_okay=False, writable=True),
    required=True,
    help="Path to save the downloaded file.",
)
@click.option(
    "--api-url",
    envvar="DCY_API_URL",
    default="https://api.dcypher.io",
    help="API base URL.",
)
def download(pk_path, auth_keys_path, file_hash, output_path, api_url):
    """Downloads a file from the remote storage API."""
    from lib.auth import sign_message_with_keys

    click.echo(f"Starting download for file hash: {file_hash}...", err=True)
    nonce = get_nonce(api_url)

    try:
        auth_keys_data = json.loads(Path(auth_keys_path).read_text())
        classic_sk = ecdsa.SigningKey.from_string(
            bytes.fromhex(Path(auth_keys_data["classic_sk_path"]).read_text()),
            curve=ecdsa.SECP256k1,
        )
        pq_keys = []
        for pq_key_info in auth_keys_data["pq_keys"]:
            pq_keys.append(
                {
                    "sk": Path(pq_key_info["sk_path"]).read_bytes(),
                    "pk_hex": pq_key_info["pk_hex"],
                    "alg": pq_key_info["alg"],
                }
            )
    except Exception as e:
        raise click.ClickException(f"Error loading auth keys: {e}")

    message = f"DOWNLOAD:{pk_path}:{file_hash}:{nonce}".encode("utf-8")
    signatures = sign_message_with_keys(
        message, {"classic_sk": classic_sk, "pq_keys": pq_keys}
    )

    url = f"{api_url}/storage/{pk_path}/{file_hash}/download"
    payload = {
        "nonce": nonce,
        "classic_signature": signatures["classic_signature"],
        "pq_signatures": signatures["pq_signatures"],
    }

    try:
        response = requests.post(url, json=payload)
        response.raise_for_status()
        with open(output_path, "wb") as f:
            f.write(response.content)
        click.echo(f"File '{file_hash}' downloaded successfully to '{output_path}'.")
    except requests.exceptions.RequestException as e:
        error_text = e.response.text if e.response else str(e)
        raise click.ClickException(f"API request failed: {error_text}")


if __name__ == "__main__":
    cli()
