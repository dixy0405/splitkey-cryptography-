import base64
import json
import secrets

import streamlit as st
from Crypto.Cipher import AES
from Crypto.Protocol.SecretSharing import Shamir


TOTAL_SHARES = 5
REQUIRED_SHARES = 3

MAX_FILE_SIZE = 10 * 1024 * 1024
MAX_PACKAGE_SIZE = 15 * 1024 * 1024

FILE_FORMAT = "splitkey-file-v1"
SHARE_FORMAT = "splitkey-share-v1"


def json_bytes(value):
    return json.dumps(
        value,
        sort_keys=True,
        separators=(",", ":"),
    ).encode("utf-8")


def encode_bytes(value):
    return base64.b64encode(value).decode("ascii")


def decode_bytes(value):
    return base64.b64decode(value, validate=True)


def clean_filename(name):
    # Remove directory components from Windows or Unix-style paths.
    name = name.replace("\\", "/").split("/")[-1]
    return name or "recovered_file"


def encrypt_file(file_bytes, filename):
    key = secrets.token_bytes(16)
    nonce = secrets.token_bytes(12)
    set_id = secrets.token_hex(16)

    header = {
        "format": FILE_FORMAT,
        "set_id": set_id,
        "filename": clean_filename(filename),
    }

    cipher = AES.new(key, AES.MODE_GCM, nonce=nonce)

    # Authenticate the filename, format, and share-set identifier too.
    cipher.update(json_bytes(header))

    ciphertext, tag = cipher.encrypt_and_digest(file_bytes)

    package = {
        **header,
        "nonce": encode_bytes(nonce),
        "tag": encode_bytes(tag),
        "ciphertext": encode_bytes(ciphertext),
    }

    shares = Shamir.split(
        REQUIRED_SHARES,
        TOTAL_SHARES,
        key,
    )

    share_files = []

    for index, share in shares:
        share_package = {
            "format": SHARE_FORMAT,
            "set_id": set_id,
            "index": index,
            "share": share.hex(),
        }

        share_files.append({
            "index": index,
            "data": json_bytes(share_package),
        })

    return {
        "filename": header["filename"],
        "set_id": set_id,
        "encrypted_data": json_bytes(package),
        "share_files": share_files,
    }


def recover_file(encrypted_bytes, uploaded_shares):
    package = json.loads(encrypted_bytes)

    if not isinstance(package, dict):
        raise ValueError("Invalid encrypted-file structure.")

    if package.get("format") != FILE_FORMAT:
        raise ValueError("This is not a supported SplitKey file.")

    set_id = package["set_id"]
    filename = package["filename"]

    if (
        not isinstance(set_id, str)
        or len(set_id) != 32
        or any(c not in "0123456789abcdef" for c in set_id)
    ):
        raise ValueError("Invalid file identifier.")

    if (
        not isinstance(filename, str)
        or not filename
        or len(filename) > 255
    ):
        raise ValueError("Invalid original filename.")

    shares = []
    seen_indexes = set()

    for uploaded in uploaded_shares:
        if uploaded.size > 4096:
            raise ValueError("A share file is unexpectedly large.")

        item = json.loads(uploaded.getvalue())

        if not isinstance(item, dict):
            raise ValueError("Invalid share-file structure.")

        if item.get("format") != SHARE_FORMAT:
            raise ValueError("One of the files is not a SplitKey share.")

        if item.get("set_id") != set_id:
            raise ValueError(
                "These shares belong to a different encrypted file."
            )

        index = item["index"]
        share_hex = item["share"]

        if type(index) is not int or not 1 <= index <= TOTAL_SHARES:
            raise ValueError("Invalid share number.")

        if index in seen_indexes:
            raise ValueError(
                "Duplicate shares detected. Select three different shares."
            )

        if not isinstance(share_hex, str) or len(share_hex) != 32:
            raise ValueError("Invalid share value.")

        share_bytes = bytes.fromhex(share_hex)

        if len(share_bytes) != 16:
            raise ValueError("Invalid share length.")

        seen_indexes.add(index)
        shares.append((index, share_bytes))

    key = Shamir.combine(shares)

    nonce = decode_bytes(package["nonce"])
    tag = decode_bytes(package["tag"])
    ciphertext = decode_bytes(package["ciphertext"])

    if len(nonce) != 12 or len(tag) != 16:
        raise ValueError("Invalid encryption parameters.")

    if len(ciphertext) > MAX_FILE_SIZE:
        raise ValueError("The encrypted content exceeds the size limit.")

    header = {
        "format": package["format"],
        "set_id": set_id,
        "filename": filename,
    }

    cipher = AES.new(key, AES.MODE_GCM, nonce=nonce)
    cipher.update(json_bytes(header))

    try:
        original_bytes = cipher.decrypt_and_verify(ciphertext, tag)
    except ValueError:
        raise ValueError(
            "Verification failed: the encrypted file or shares "
            "are incorrect or have been modified."
        ) from None

    return clean_filename(filename), original_bytes


st.set_page_config(
    page_title="SplitKey File Protection",
    page_icon="🔐",
    layout="centered",
)

st.title("🔐 SplitKey")
st.subheader("File protection with shared key recovery")

st.write(
    "Encrypt a file and split its key into five shares. "
    "Any three different shares from the same set can recover the file."
)

st.caption(
    "Local college-project prototype • AES-128-GCM • "
    "Shamir 3-of-5 sharing • Maximum original file size: 10 MB"
)

if "encrypted_result" not in st.session_state:
    st.session_state.encrypted_result = None

encrypt_tab, recover_tab = st.tabs([
    "1. Encrypt & Split",
    "2. Recover File",
])


with encrypt_tab:
    st.header("Protect a file")

    source_file = st.file_uploader(
        "Choose a PDF, image, text file, or another document",
        key="source_file",
    )

    if st.button("Encrypt file and create shares", type="primary"):
        st.session_state.encrypted_result = None

        if source_file is None:
            st.error("Upload a file first.")

        elif source_file.size > MAX_FILE_SIZE:
            st.error("Choose a file no larger than 10 MB.")

        else:
            with st.spinner("Encrypting and creating shares…"):
                st.session_state.encrypted_result = encrypt_file(
                    source_file.getvalue(),
                    source_file.name,
                )

    result = st.session_state.encrypted_result

    if result is not None:
        short_id = result["set_id"][:8]

        st.success(
            f'Encrypted: {result["filename"]}. '
            "Download the encrypted file and all five shares."
        )

        st.download_button(
            "Download encrypted file",
            data=result["encrypted_data"],
            file_name=(
                f'{result["filename"]}.{short_id}.splitkey'
            ),
            mime="application/octet-stream",
            on_click="ignore",
        )

        st.subheader("Download the five shares")

        for item in result["share_files"]:
            index = item["index"]

            st.download_button(
                label=f"Download share {index}",
                data=item["data"],
                file_name=f"share_{index}_{short_id}.json",
                mime="application/json",
                key=f"download_share_{index}",
                on_click="ignore",
            )

        st.warning(
            "Each share is confidential. Distribute shares separately "
            "to five trusted people. Anyone holding three shares and "
            "the encrypted file can recover the document."
        )

        st.caption(
            "Generating another set replaces the download buttons. "
            "Previously downloaded files still work with their matching shares."
        )


with recover_tab:
    st.header("Recover your original file")

    encrypted_upload = st.file_uploader(
        "Upload the encrypted .splitkey file",
        type=["splitkey"],
        key="encrypted_upload",
    )

    share_uploads = st.file_uploader(
        "Upload exactly three different matching share files",
        type=["json"],
        accept_multiple_files=True,
        key="share_uploads",
    )

    st.caption(
        f"{len(share_uploads)} of 3 required share files selected."
    )

    if st.button("Recover original file", type="primary"):
        if encrypted_upload is None:
            st.error("Upload the encrypted file first.")

        elif encrypted_upload.size > MAX_PACKAGE_SIZE:
            st.error("The encrypted package is too large.")

        elif len(share_uploads) != REQUIRED_SHARES:
            st.error("Upload exactly three different share files.")

        else:
            try:
                with st.spinner("Reconstructing key and verifying file…"):
                    filename, original_bytes = recover_file(
                        encrypted_upload.getvalue(),
                        share_uploads,
                    )

                st.success(
                    "File recovered and integrity verified successfully."
                )

                st.download_button(
                    "Download recovered original",
                    data=original_bytes,
                    file_name=filename,
                    mime="application/octet-stream",
                    on_click="ignore",
                )

            except (ValueError, KeyError, TypeError) as error:
                st.error(f"Recovery failed: {error}")


st.divider()

with st.expander("How the project works"):
    st.markdown("""
    1. A random 128-bit AES key is generated for each encryption.
    2. AES-GCM encrypts the file and produces an authentication tag.
    3. Shamir's scheme splits the AES key into five shares.
    4. Any three matching shares reconstruct the key.
    5. AES-GCM verifies the encrypted data before releasing the original.

    The encrypted package includes the original filename in readable form.
    The file contents are encrypted.

    This local prototype handles the original file, key, and shares in the
    Python process. It does not provide end-to-end encryption against the
    computer running the application.
    """)