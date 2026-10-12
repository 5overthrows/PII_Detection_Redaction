from __future__ import annotations

import mimetypes
import tempfile
from pathlib import Path

import streamlit as st

from backend.file_redaction import SUPPORTED_EXTENSIONS, redact_file


st.set_page_config(
    page_title="PII Redaction",
    page_icon="🔒",
    layout="centered",
)

st.title("PII Redaction")
st.write(
    "Upload a Word document, PowerPoint presentation, PDF, image, or text file. "
    "The app detects PII in document text and embedded images, then provides a "
    "redacted copy to download."
)
st.info(
    "Files are processed locally by this app. OCR scans standalone images, scanned "
    "PDF pages, and embedded images in Word and PowerPoint files. The first OCR run "
    "may download models and requires an internet connection."
)

uploaded_file = st.file_uploader(
    "Choose a file",
    type=sorted(extension.removeprefix(".") for extension in SUPPORTED_EXTENSIONS),
    help=(
        "Supported: PDF, DOCX, PPTX, TXT, CSV, BMP, GIF, JPEG/JPG, PNG, "
        "TIF/TIFF, and WEBP."
    ),
)

if uploaded_file is not None:
    st.caption(f"Selected file: {uploaded_file.name}")

    if st.button("Redact PII", type="primary", use_container_width=True):
        source_name = Path(uploaded_file.name).name
        extension = Path(source_name).suffix.lower()
        output_name = f"{Path(source_name).stem}_redacted{extension}"

        with st.spinner("Detecting and redacting PII..."):
            try:
                with tempfile.TemporaryDirectory(prefix="pii-redaction-") as temp_dir:
                    input_path = Path(temp_dir) / source_name
                    output_path = Path(temp_dir) / output_name
                    input_path.write_bytes(uploaded_file.getvalue())
                    redact_file(input_path, output_path)
                    redacted_bytes = output_path.read_bytes()
            except Exception as error:
                st.error(f"Redaction failed: {error}")
            else:
                mime_type = mimetypes.guess_type(output_name)[0] or "application/octet-stream"
                st.success("Redaction complete.")
                st.download_button(
                    "Download redacted file",
                    data=redacted_bytes,
                    file_name=output_name,
                    mime=mime_type,
                    use_container_width=True,
                )
