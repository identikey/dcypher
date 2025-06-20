import click
from lib import pre
import json
import requests
import hashlib
import os


API_BASE_URL = os.environ.get("API_BASE_URL", "http://127.0.0.1:8000")


def get_nonce():
    """Fetches a nonce from the API."""
    try:
        response = requests.get(f"{API_BASE_URL}/nonce")
        response.raise_for_status()
        return response.json()["nonce"]
    except requests.exceptions.RequestException as e:
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
@click.option("--data", help="String to encrypt.")
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
        input_data = list(data.encode("utf-8"))

    click.echo("Encrypting data...", err=True)
    ciphertexts = pre.encrypt(cc, pk, input_data)
    serialized_ciphertexts = [pre.serialize(ct) for ct in ciphertexts]

    with open(output, "w") as f:
        json.dump({"length": len(input_data), "ciphertexts": serialized_ciphertexts}, f)

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

    length = ciphertext_data.get("length")

    if "ciphertexts" in ciphertext_data:
        serialized_items = ciphertext_data["ciphertexts"]
        ciphertexts = [
            pre.deserialize_ciphertext(s_item) for s_item in serialized_items
        ]
    else:  # Legacy single-ciphertext format
        serialized_item = ciphertext_data["ciphertext"]
        ciphertexts = [pre.deserialize_ciphertext(serialized_item)]

    click.echo("Decrypting data...", err=True)
    decrypted_data = pre.decrypt(cc, sk, ciphertexts, length)

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

    length = ciphertext_data.get("length")

    if "ciphertexts" in ciphertext_data:
        serialized_items = ciphertext_data["ciphertexts"]
        ciphertexts = [
            pre.deserialize_ciphertext(s_item) for s_item in serialized_items
        ]
    else:  # Legacy single-ciphertext format
        serialized_item = ciphertext_data["ciphertext"]
        ciphertexts = [pre.deserialize_ciphertext(serialized_item)]

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
@click.option("--pk-path", help="Path to the classic public key file.", required=True)
@click.option(
    "--auth-keys-path",
    help="Path to the JSON file containing authentication key details.",
    required=True,
)
@click.option(
    "--file-path",
    help="Path to the (encrypted) file to upload.",
    type=click.Path(exists=True, dir_okay=False),
    required=True,
)
def upload(pk_path, auth_keys_path, file_path):
    """Uploads a file to the dCypher API."""
    click.echo("Starting file upload process...", err=True)

    # Load authentication keys
    from lib.auth import sign_message
    from lib.pq_auth import get_oqs_sig_from_path

    try:
        with open(auth_keys_path, "r") as f:
            auth_keys = json.load(f)
        with open(auth_keys["classic_sk_path"], "r") as f:
            classic_sk_hex = f.read()
    except (IOError, json.JSONDecodeError, KeyError) as e:
        raise click.ClickException(f"Error loading auth keys: {e}")

    # Calculate file hash
    with open(file_path, "rb") as f:
        file_content = f.read()
    file_hash = hashlib.sha256(file_content).hexdigest()

    # Get nonce
    nonce = get_nonce()

    # Construct and sign message
    message = f"UPLOAD:{pk_path}:{file_hash}:{nonce}".encode("utf-8")
    classic_sig = sign_message(classic_sk_hex, message)
    pq_signatures = []
    for pq_key in auth_keys["pq_keys"]:
        sig_obj = get_oqs_sig_from_path(pq_key["sk_path"], pq_key["alg"])
        pq_signatures.append(
            {
                "public_key": pq_key["pk_hex"],
                "signature": sig_obj.sign(message).hex(),
                "alg": pq_key["alg"],
            }
        )

    # Prepare and send request
    files = {"file": (file_path, file_content)}
    data = {
        "nonce": nonce,
        "file_hash": file_hash,
        "classic_signature": classic_sig,
        "pq_signatures": json.dumps(pq_signatures),
    }

    try:
        response = requests.post(
            f"{API_BASE_URL}/storage/{pk_path}", files=files, data=data
        )
        response.raise_for_status()
        click.echo("File uploaded successfully.", err=True)
        click.echo(json.dumps(response.json(), indent=2))
    except requests.exceptions.RequestException as e:
        error_text = e.response.text if e.response else "No response from server."
        raise click.ClickException(f"API request failed: {e}\n{error_text}")


@cli.command("download")
@click.option("--pk-path", help="Path to the classic public key.", required=True)
@click.option(
    "--auth-keys-path",
    help="Path to the JSON file containing authentication key details.",
    required=True,
)
@click.option("--file-hash", help="Hash of the file to download.", required=True)
@click.option(
    "--output-path",
    help="Path to save the downloaded file.",
    type=click.Path(dir_okay=False),
    required=True,
)
def download(pk_path, auth_keys_path, file_hash, output_path):
    """Downloads a file from the dCypher API."""
    click.echo(f"Starting download for file hash: {file_hash}...", err=True)

    # Load authentication keys
    from lib.auth import sign_message
    from lib.pq_auth import get_oqs_sig_from_path

    try:
        with open(auth_keys_path, "r") as f:
            auth_keys = json.load(f)
        with open(auth_keys["classic_sk_path"], "r") as f:
            classic_sk_hex = f.read()
    except (IOError, json.JSONDecodeError, KeyError) as e:
        raise click.ClickException(f"Error loading auth keys: {e}")

    # Get nonce
    nonce = get_nonce()

    # Construct and sign message
    message = f"DOWNLOAD:{pk_path}:{file_hash}:{nonce}".encode("utf-8")
    classic_sig = sign_message(classic_sk_hex, message)
    pq_signatures = []
    for pq_key in auth_keys["pq_keys"]:
        sig_obj = get_oqs_sig_from_path(pq_key["sk_path"], pq_key["alg"])
        pq_signatures.append(
            {
                "public_key": pq_key["pk_hex"],
                "signature": sig_obj.sign(message).hex(),
                "alg": pq_key["alg"],
            }
        )

    # Prepare and send request
    payload = {
        "nonce": nonce,
        "classic_signature": classic_sig,
        "pq_signatures": pq_signatures,
    }

    try:
        response = requests.post(
            f"{API_BASE_URL}/storage/{pk_path}/{file_hash}/download", json=payload
        )
        response.raise_for_status()
        with open(output_path, "wb") as f:
            f.write(response.content)
        click.echo(f"File successfully downloaded to {output_path}", err=True)
    except requests.exceptions.RequestException as e:
        error_text = e.response.text if e.response else "No response from server."
        raise click.ClickException(f"API request failed: {e}\n{error_text}")


if __name__ == "__main__":
    cli()
