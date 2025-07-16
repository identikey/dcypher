from pydantic import BaseModel, Field
from typing import List, Optional


class PqSignature(BaseModel):
    """Represents a post-quantum signature."""

    public_key: str  # hex-encoded post-quantum public key
    signature: str  # hex-encoded post-quantum signature
    alg: str  # post-quantum algorithm used


class CreateAccountRequest(BaseModel):
    public_key: str = Field(
        ..., description="Hex-encoded uncompressed SECP256k1 public key."
    )
    signature: str = Field(
        ..., description="Hex-encoded DER signature from the classic key."
    )
    ml_dsa_signature: PqSignature = Field(
        ..., description="Mandatory ML-DSA-87 signature."
    )
    additional_pq_signatures: list[PqSignature] = Field(
        [], description="Optional list of additional PQ signatures."
    )
    nonce: str = Field(..., description="Time-based nonce provided by the server.")
    pre_public_key_hex: Optional[str] = Field(
        None, description="Optional hex-encoded public key for Proxy Recryption."
    )


class AddPqKeysRequest(BaseModel):
    """Request to add new PQ keys to an account."""

    new_pq_signatures: list[PqSignature] = Field(
        ..., description="New PQ keys and their corresponding authorization signatures."
    )
    classic_signature: str = Field(
        ...,
        description="Signature from the root classic key authorizing the operation.",
    )
    existing_pq_signatures: list[PqSignature] = Field(
        ..., description="Signatures from all existing PQ keys on the account."
    )
    nonce: str = Field(..., description="Time-based nonce provided by the server.")


class RemovePqKeysRequest(BaseModel):
    """Request to remove PQ keys from an account."""

    algs_to_remove: list[str] = Field(
        ..., description="A list of the algorithm names for the PQ keys to be removed."
    )
    classic_signature: str = Field(
        ...,
        description="Signature from the root classic key authorizing the operation.",
    )
    pq_signatures: list[PqSignature] = Field(
        ..., description="Signatures from all existing PQ keys on the account."
    )
    nonce: str = Field(..., description="Time-based nonce provided by the server.")


class DownloadFileRequest(BaseModel):
    """Request to download a file from the block store."""

    classic_signature: str = Field(
        ..., description="Signature from the root classic key authorizing the download."
    )
    pq_signatures: list[PqSignature] = Field(
        ..., description="Signatures from all existing PQ keys on the account."
    )
    nonce: str = Field(..., description="Time-based nonce provided by the server.")
    compressed: bool = Field(
        False, description="Whether to return the file compressed if possible."
    )


class DownloadChunkRequest(BaseModel):
    """Request to download a single file chunk."""

    chunk_hash: str = Field(..., description="SHA256 hash of the chunk's content.")
    classic_signature: str = Field(
        ..., description="Signature from the root classic key authorizing the download."
    )
    pq_signatures: list[PqSignature] = Field(
        ..., description="Signatures from all existing PQ keys on the account."
    )
    nonce: str = Field(..., description="Time-based nonce provided by the server.")
    compressed: bool = Field(
        False,
        description="Whether to return the chunk compressed if stored compressed.",
    )


class DownloadConcatenatedRequest(BaseModel):
    """Request to download all chunks concatenated as a single gzip file."""

    classic_signature: str = Field(
        ..., description="Signature from the root classic key authorizing the download."
    )
    pq_signatures: list[PqSignature] = Field(
        ..., description="Signatures from all existing PQ keys on the account."
    )
    nonce: str = Field(..., description="Time-based nonce provided by the server.")


class UploadFileRequest(BaseModel):
    """Request to upload a file to the block store."""

    file_hash: str = Field(..., description="SHA256 hash of the entire file content.")
    classic_signature: str = Field(
        ..., description="Signature from the root classic key authorizing the upload."
    )
    pq_signatures: list[PqSignature] = Field(
        ..., description="Signatures from all existing PQ keys on the account."
    )
    nonce: str = Field(..., description="Time-based nonce provided by the server.")


class UploadChunkRequest(BaseModel):
    """Request to upload a single file chunk."""

    chunk_hash: str = Field(..., description="SHA256 hash of the chunk's content.")
    chunk_index: int = Field(..., description="The zero-based index of this chunk.")
    total_chunks: int = Field(
        ..., description="The total number of chunks for the file."
    )
    compressed: bool = Field(False, description="Whether the chunk is gzip compressed.")
    classic_signature: str = Field(
        ...,
        description="Signature from the root classic key authorizing the chunk upload.",
    )
    pq_signatures: list[PqSignature] = Field(
        ..., description="Signatures from all existing PQ keys on the account."
    )
    nonce: str = Field(..., description="Time-based nonce provided by the server.")


# --- Data Models ---


class PqPublicKey(BaseModel):
    """Represents a post-quantum public key."""

    public_key: str
    alg: str


class Account(BaseModel):
    """Represents a user account."""

    classic_pk: str
    pq_keys: List[PqPublicKey]


class Chunk(BaseModel):
    """Represents a single chunk of a file."""

    chunk_id: str
    chunk_index: int
    data: bytes


class Block(BaseModel):
    """Represents a block, which is a collection of chunks (i.e., a file)."""

    block_id: str
    chunk_ids: List[str]
    total_chunks: int


class RegisterFileRequest(BaseModel):
    nonce: str
    file_hash: str
    filename: str
    size: int
    content_type: str
    classic_signature: str
    pq_signatures: List[PqSignature]
