"""
Optiv Consulting — Enterprise PII Detection & Redaction Gateway
Case Study-2: Text Analysis and PII Detection for Cadence Financial Services
"""
import os
import io
import json
import tempfile
import pandas as pd
import streamlit as st

from extractors.unified_extractor import UnifiedExtractor
from detector.pii_engine import PIIEngine
from redactor.redaction_engine import RedactionEngine
from audit.risk_assessment import RiskAssessmentEngine

# Page configuration
st.set_page_config(
    page_title="Optiv | Cadence PII Gateway",
    page_icon="🛡️",
    layout="wide",
    initial_sidebar_state="expanded"
)

# Custom Styling (Optiv Navy #0e2b5c, Optiv Accent #dc5028)
st.markdown("""
<style>
    .optiv-header {
        background: linear-gradient(135deg, #0e2b5c 0%, #173f82 100%);
        padding: 24px 30px;
        border-radius: 12px;
        color: white;
        margin-bottom: 25px;
        box-shadow: 0 4px 15px rgba(14, 43, 92, 0.2);
    }
    .optiv-title {
        font-size: 28px;
        font-weight: 800;
        margin: 0;
        color: #ffffff;
        letter-spacing: -0.5px;
    }
    .optiv-sub {
        font-size: 15px;
        color: #fca311;
        margin-top: 5px;
        font-weight: 500;
    }
    .metric-card {
        background: #ffffff;
        padding: 16px 20px;
        border-radius: 10px;
        border-left: 5px solid #0e2b5c;
        box-shadow: 0 2px 8px rgba(0,0,0,0.06);
    }
    .metric-crit { border-left-color: #e63946 !important; }
    .metric-high { border-left-color: #f77f00 !important; }
    .metric-med  { border-left-color: #fcbf49 !important; }
    .metric-pass { border-left-color: #2a9d8f !important; }
    
    .badge-crit { background: #fee2e2; color: #991b1b; padding: 4px 10px; border-radius: 20px; font-weight: 700; font-size: 12px; }
    .badge-high { background: #ffedd5; color: #9a3412; padding: 4px 10px; border-radius: 20px; font-weight: 700; font-size: 12px; }
    .badge-med  { background: #fef9c3; color: #854d0e; padding: 4px 10px; border-radius: 20px; font-weight: 700; font-size: 12px; }
    .badge-low  { background: #dcfce7; color: #166534; padding: 4px 10px; border-radius: 20px; font-weight: 700; font-size: 12px; }

    .tag-gov   { background: #fee2e2; color: #b91c1c; font-weight: 600; padding: 2px 6px; border-radius: 4px; }
    .tag-fin   { background: #ffedd5; color: #c2410c; font-weight: 600; padding: 2px 6px; border-radius: 4px; }
    .tag-per   { background: #f3e8ff; color: #7e22ce; font-weight: 600; padding: 2px 6px; border-radius: 4px; }
    .tag-con   { background: #e0f2fe; color: #0369a1; font-weight: 600; padding: 2px 6px; border-radius: 4px; }
    .tag-corp  { background: #dcfce7; color: #15803d; font-weight: 600; padding: 2px 6px; border-radius: 4px; }
</style>
""", unsafe_allow_html=True)

# App Header
st.markdown("""
<div class="optiv-header">
    <div style="display:flex; justify-content:space-between; align-items:center;">
        <div>
            <div class="optiv-title">🛡️ Optiv Consulting — PII Detection & LLM Redaction Gateway</div>
            <div class="optiv-sub">Client Engagement: Cadence Financial Services (New York) · Case Study-2 Solution</div>
        </div>
        <div style="text-align:right; font-size:12px; color:#e2e8f0;">
            <div>Policy: Cadence AI Directive 2026-R4</div>
            <div>Compliance: GLBA · NYDFS 23 NYCRR 500 · GDPR</div>
        </div>
    </div>
</div>
""", unsafe_allow_html=True)

# Sample directory
BASE_DIR = os.path.dirname(os.path.abspath(__file__))
SAMPLES_DIR = os.path.join(BASE_DIR, "samples")
OUTPUTS_DIR = os.path.join(BASE_DIR, "outputs")
os.makedirs(OUTPUTS_DIR, exist_ok=True)

# Sidebar
st.sidebar.title("Configuration & Mode")

st.sidebar.markdown("""
<div style="background:#f1f5f9; padding:12px; border-radius:8px; border-left:4px solid #10b981; margin-bottom:15px;">
    <div style="font-size:12px; font-weight:700; color:#0f172a;">🤖 AI Privacy Filter Engine</div>
    <div style="font-size:11px; color:#059669; font-weight:600;">● openai/privacy-filter (1.5B Local)</div>
    <div style="font-size:11px; color:#475569;">Tier 1: Deterministic Checksums & RegEx</div>
    <div style="font-size:11px; color:#475569;">Tier 2: Bidirectional Token Classifier</div>
    <div style="font-size:11px; color:#475569;">Tier 3: Contextual Cadence Heuristics</div>
    <div style="font-size:11px; color:#475569;">Tier 4: Microsoft Presidio NER</div>
</div>
""", unsafe_allow_html=True)

sample_options = {
    "Select a preloaded artifact...": None,
    "💼 Cadence Wealth Portfolio Review (PPTX)": "cadence_wealth_portfolio_review.pptx",
    "📄 Cadence Commercial Credit Evaluation (PDF)": "cadence_credit_policy_evaluation.pdf",
    "📑 Cadence Group Risk Management Policy v6.0 (35-Page Scanned PDF)": "Cadence_Group_Risk_Management_Policy__v6.0.pdf",
    "📝 Cadence Internal Audit Memo (TXT)": "cadence_internal_audit_memo.txt",
    "🧪 Multi-National ID & Banking Test (DOCX)": "pii_redaction_test.docx",
    "👤 Candidate Personal Profile (DOCX)": "input.docx"
}

st.sidebar.markdown("### 📂 Evidence Ingestion")
selected_sample_label = st.sidebar.selectbox("Choose Sample Artifact", list(sample_options.keys()))
uploaded_file = st.sidebar.file_uploader("Or Upload Custom Document", type=["docx", "pptx", "pdf", "txt", "csv"])

# Determine file to process
active_file_path = None
active_file_name = None

if uploaded_file is not None:
    suffix = os.path.splitext(uploaded_file.name)[1].lower()
    temp_handle = tempfile.NamedTemporaryFile(prefix="optiv_upload_", suffix=suffix, delete=False)
    temp_path = temp_handle.name
    temp_handle.close()
    with open(temp_path, "wb") as f:
        f.write(uploaded_file.getbuffer())
    active_file_path = temp_path
    active_file_name = uploaded_file.name
elif selected_sample_label != "Select a preloaded artifact...":
    sample_fname = sample_options[selected_sample_label]
    active_file_path = os.path.join(SAMPLES_DIR, sample_fname)
    active_file_name = sample_fname

# Tabs
tab1, tab2, tab3 = st.tabs([
    "🔍 Document Inspector & Redaction Gateway", 
    "📊 Portfolio Compliance & Audit Dashboard", 
    "📐 Solution Architecture & Engineering Blueprint"
])

# ==========================================
# TAB 1: Document Inspector & Redactor
# ==========================================
with tab1:
    if not active_file_path:
        st.info("👈 Please select a preloaded Cadence sample artifact or upload a document from the left sidebar to begin.")
        st.markdown("""
        #### Available Preloaded Evidence Artifacts:
        1. **`cadence_wealth_portfolio_review.pptx`**: Multi-slide presentation containing HNW client portfolios, SSNs, bank accounts, wire notes.
        2. **`cadence_credit_policy_evaluation.pdf`**: Multi-page underwriting document with applicant SSNs, passports, NY driver licenses, credit card numbers, and banking balances.
        3. **`cadence_internal_audit_memo.txt`**: Internal security incident memo with contractor credentials, PAN, Aadhaar, and wire numbers.
        4. **`pii_redaction_test.docx`**: Word document containing tables with international IDs (PAN, Aadhaar, Passport), banking IFSC, and phone numbers.
        5. **`input.docx`**: Candidate profile with email, phone, address, and student credentials.
        """)
    else:
        cache_key = f"proc_{active_file_name}_{os.path.getmtime(active_file_path)}"
        if "doc_cache" not in st.session_state or st.session_state.get("current_cache_key") != cache_key:
            with st.spinner("Executing Ingestion, Structural Analysis & Multi-Tier PII Detection..."):
                # 1. Extraction
                doc = UnifiedExtractor.extract_document(active_file_path)
                # 2. Detection
                entities = PIIEngine.detect_in_document(doc)
                # 3. Redaction
                redacted_doc, vault = RedactionEngine.redact_document(doc, entities)
                # 4. Audit
                audit_report = RiskAssessmentEngine.generate_audit_report(doc, entities)
                # 5. LLM Payload
                llm_payload = RedactionEngine.generate_llm_payload(redacted_doc)
                out_native_path = os.path.join(OUTPUTS_DIR, f"redacted_{active_file_name}")
                RedactionEngine.export_redacted_document(active_file_path, out_native_path, entities)
                output_check = RedactionEngine.verify_redacted_output(out_native_path, source_path=active_file_path)

                st.session_state["doc_cache"] = (doc, entities, redacted_doc, vault, audit_report, llm_payload, out_native_path, output_check)
                st.session_state["current_cache_key"] = cache_key

        doc, entities, redacted_doc, vault, audit_report, llm_payload, out_native_path, output_check = st.session_state["doc_cache"]

        # Top Metric Banner
        c1, c2, c3, c4 = st.columns(4)
        with c1:
            st.metric("Total Words & Blocks", f"{doc.total_words} words", f"{doc.total_blocks} structural blocks")
        with c2:
            preservation = output_check.get("structural_retention", {}).get("score")
            preservation_label = f"{preservation * 100:.1f}%" if preservation is not None else "N/A"
            st.metric("Format preservation", preservation_label, "Structural-count proxy; visual review required")
        with c3:
            st.metric("Sensitive PII Detected", f"{len(entities)} instances", f"{len(vault.reverse_map)} surrogate tokens")
        with c4:
            st.metric("Cadence Exposure Score", f"{audit_report.exposure_score}/100", f"Risk: {audit_report.exposure_level}")

        st.divider()

        # Layout: Left = Document View / Comparison, Right = Traceability & LLM Payload
        col_doc, col_audit = st.columns([1.1, 1.1])

        with col_doc:
            st.subheader(f"📄 Document Content: `{active_file_name}`")
            view_mode = st.radio("Display View", ["Sanitized Markdown (LLM Input)", "Side-by-Side Comparison", "Raw Extracted Blocks"], horizontal=True)

            if view_mode == "Sanitized Markdown (LLM Input)":
                st.markdown("##### Cleaned & Redacted Text Intact for LLM Processing")
                st.markdown("> **Format preservation:** measured against the saved native output below; visual layout still needs review.")
                st.code(redacted_doc.get_structured_markdown(), language="markdown")

            elif view_mode == "Side-by-Side Comparison":
                sub_c1, sub_c2 = st.columns(2)
                with sub_c1:
                    st.caption("🔴 Original Extracted (Raw PII Exposed)")
                    st.text_area("Original", doc.get_structured_markdown(), height=450, disabled=True)
                with sub_c2:
                    st.caption("🟢 Redacted draft (re-scan status shown below)")
                    st.text_area("Sanitized", redacted_doc.get_structured_markdown(), height=450, disabled=True)

            elif view_mode == "Raw Extracted Blocks":
                st.write(f"Total Structural Elements: {len(doc.blocks)}")
                for b in doc.blocks[:15]:
                    with st.expander(f"Block: `{b.block_id}` | Type: `{b.block_type}` | Loc: {b.location}"):
                        st.write(b.text)

        with col_audit:
            st.subheader("🛡️ PII Audit & Traceability Registry")

            # Category filter
            cats = ["All Categories"] + sorted(list(set(e.category for e in entities)))
            selected_cat = st.selectbox("Filter by Category", cats)

            filtered_trace = [
                r for r in audit_report.traceability_records 
                if selected_cat == "All Categories" or r["category"] == selected_cat
            ]

            if filtered_trace:
                df_trace = pd.DataFrame(filtered_trace)[[
                    "id", "entity_type", "severity", "masked_value", "surrogate_token", "confidence", "source", "location"
                ]]
                st.dataframe(df_trace, use_container_width=True, height=260)
            else:
                st.info("No entities found for the selected category.")

            st.markdown("##### 🤖 Downstream LLM Prompt Dispatch Simulation")
            with st.expander("Inspect Sanitized Payload Sent to Cadence AI Agent", expanded=True):
                st.markdown(f"**Prompt Guard Status:** `{llm_payload['pii_leakage_risk']}`")
                st.markdown("**System Prompt Directive:**")
                st.info(llm_payload["system_instruction"])
                st.markdown("**Payload Preview:**")
        # Embedded Image Intelligence Section (PyMuPDF)
        image_records = doc.metadata.get("image_records", [])
        if image_records:
            st.markdown("---")
            st.subheader("🖼️ Embedded Image Intelligence & Visual Redaction (PyMuPDF)")
            st.caption("Deep inspection of raster graphics, document scans, and barcodes embedded within PDF streams.")

            im_c1, im_c2, im_c3, im_c4 = st.columns(4)
            with im_c1:
                st.metric("Total Images Extracted", f"{len(image_records)} assets")
            with im_c2:
                qr_count = sum(len(r.barcode_data) for r in image_records)
                st.metric("Decoded Barcodes / QRs", f"{qr_count} found")
            with im_c3:
                pii_img_count = sum(1 for r in image_records if r.has_pii)
                st.metric("Images with Sensitive PII", f"{pii_img_count} flagged")
            with im_c4:
                total_kb = sum(r.size_kb for r in image_records)
                st.metric("Total Visual Payload", f"{total_kb:.1f} KB")

            with st.expander("🔍 View Embedded Image Gallery & Inspection Details", expanded=True):
                for r_idx, rec in enumerate(image_records):
                    st.markdown(f"**Image `{rec.image_id}`** — Page {rec.page_number} | XREF `{rec.xref}` | `{rec.classification}` | Dimensions: `{rec.dimensions_str}` ({rec.format.upper()}, {rec.size_kb} KB)")
                    ig_c1, ig_c2, ig_c3 = st.columns([1, 1.3, 1])
                    with ig_c1:
                        st.caption("📷 Original Embedded Graphic")
                        st.image(rec.image_bytes, use_container_width=True)
                    with ig_c2:
                        st.caption("📋 Extracted Text & Security Metadata")
                        st.write(f"- **Bounding Box (pt):** `{rec.bbox}`")
                        st.write(f"- **MD5 Fingerprint:** `{rec.md5_hash[:16]}...`")
                        if rec.barcode_data:
                            for bc in rec.barcode_data:
                                st.code(f"[{bc['type']}] {bc['data']}", language="text")
                        if rec.ocr_text:
                            st.write(f"- **OCR Text:** `{rec.ocr_text}`")
                        if rec.detected_entities:
                            st.markdown("**Sensitive Identifiers Detected:**")
                            for de in rec.detected_entities:
                                st.markdown(f"<span class='badge-crit'>{de.entity_type}</span>: `{de.value}`", unsafe_allow_html=True)
                        else:
                            st.write("- **PII Status:** No sensitive personal identifiers detected.")
                    with ig_c3:
                        st.caption("🛡️ Redacted Output Preview")
                        from extractors.pdf_image_processor import PDFImageProcessor
                        redacted_bytes = PDFImageProcessor.generate_redacted_placeholder(rec.width, rec.height, "SENSITIVE PII MASKED")
                        st.image(redacted_bytes, use_container_width=True)
                    st.divider()

        st.divider()

        # Export & Download Section
        st.subheader("📥 Export & Compliance Deliverables")

        ext = os.path.splitext(active_file_name)[1].lower()
        mime_map = {
            ".pptx": "application/vnd.openxmlformats-officedocument.presentationml.presentation",
            ".docx": "application/vnd.openxmlformats-officedocument.wordprocessingml.document",
            ".pdf": "application/pdf",
            ".txt": "text/plain",
            ".csv": "text/csv",
        }
        format_label = ext.replace(".", "").upper()
        native_mime = mime_map.get(ext, "application/octet-stream")

        with open(out_native_path, "rb") as f:
            native_bytes = f.read()

        if output_check["scan_complete"] and output_check["residual_entities"] == 0:
            st.success("Saved output re-scan found no possible PII matches.")
        else:
            st.warning(f"Possible PII matches found: {output_check['residual_entities']}. The file is available to download; review it before use.")
        structure_check = output_check.get("structural_retention", {})
        st.caption(f"Format preservation proxy: {structure_check.get('score')} — {structure_check.get('method')}")
        if output_check.get("warnings"):
            st.warning("Coverage warnings: " + " ".join(output_check["warnings"]))

        d1, d2, d3 = st.columns(3)
        with d1:
            st.download_button(
                f"⬇️ Download Redacted {format_label}",
                data=native_bytes,
                file_name=f"redacted_{active_file_name}",
                mime=native_mime,
                type="primary"
            )
        with d2:
            st.download_button(
                "⬇️ Download Sanitized Text",
                data=redacted_doc.get_structured_markdown(),
                file_name=f"sanitized_{active_file_name}.txt",
                mime="text/plain"
            )
        with d3:
            trace_csv = pd.DataFrame(audit_report.traceability_records).to_csv(index=False)
            st.download_button(
                "⬇️ Download Audit Log (CSV)",
                data=trace_csv,
                file_name=f"audit_traceability_{active_file_name}.csv",
                mime="text/csv"
            )
        st.caption("The reversible token map is kept in memory for this session and is not exported as plaintext because it contains original PII.")

# ==========================================
# TAB 2: Portfolio Compliance & Audit Dashboard
# ==========================================
with tab2:
    st.subheader("📊 Portfolio-Level Third-Party & Vendor Evidence Risk Exposure")
    st.markdown("Batch assessment across all evidence artifacts submitted by Cadence business units.")

    all_sample_files = [
        "input.docx",
        "pii_redaction_test.docx",
        "cadence_wealth_portfolio_review.pptx",
        "cadence_credit_policy_evaluation.pdf",
        "cadence_internal_audit_memo.txt"
    ]

    if "portfolio_cache" not in st.session_state:
        portfolio_data = []
        cat_aggregate = {}
        sev_aggregate = {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0}

        for sf in all_sample_files:
            p = os.path.join(SAMPLES_DIR, sf)
            if os.path.exists(p):
                d = UnifiedExtractor.extract_document(p)
                e = PIIEngine.detect_in_document(d)
                rep = RiskAssessmentEngine.generate_audit_report(d, e)
                portfolio_data.append({
                    "Artifact": sf,
                    "Format": d.file_type.upper(),
                    "Words": d.total_words,
                    "Output Preservation": "Not measured in inventory view",
                    "Total PII": rep.total_pii_count,
                    "Exposure Score": rep.exposure_score,
                    "Risk Rating": rep.exposure_level
                })
                for c, cnt in rep.breakdown_by_category.items():
                    cat_aggregate[c] = cat_aggregate.get(c, 0) + cnt
                for s, cnt in rep.breakdown_by_severity.items():
                    sev_aggregate[s] += cnt

        st.session_state["portfolio_cache"] = (portfolio_data, cat_aggregate, sev_aggregate)

    portfolio_data, cat_aggregate, sev_aggregate = st.session_state["portfolio_cache"]

    port_df = pd.DataFrame(portfolio_data)

    p_col1, p_col2 = st.columns([1.2, 0.8])
    with p_col1:
        st.markdown("##### Evidence Artifacts Inventory & Exposure Scores")
        st.dataframe(port_df, use_container_width=True)

    with p_col2:
        st.markdown("##### Portfolio Severity Breakdown")
        sev_df = pd.DataFrame(list(sev_aggregate.items()), columns=["Severity", "Count"])
        st.bar_chart(sev_df.set_index("Severity"))

    st.divider()

    st.markdown("##### PII Distribution by Category Across Ingested Portfolio")
    cat_df = pd.DataFrame(list(cat_aggregate.items()), columns=["Category", "Count"]).sort_values(by="Count", ascending=False)
    st.bar_chart(cat_df.set_index("Category"))

    st.markdown("##### Applicable Regulatory Compliance Enforcement")
    r1, r2, r3 = st.columns(3)
    with r1:
        st.markdown("""
        **GLBA Safeguards Rule § 314.4**
        - Mandate: Protection of customer financial information.
        - Enforcement: Banking sub-processors and cloud models prohibited from receiving unencrypted SSNs, account numbers, or wire routing.
        - Optiv Guard: **Tokenization is applied to detected spans; results require output re-scan.**
        """)
    with r2:
        st.markdown("""
        **NYDFS 23 NYCRR 500**
        - Mandate: Cybersecurity requirements for financial services firms in NY.
        - Enforcement: Strict limitation on unauthorized data access and sub-contractor data handling.
        - Optiv Guard: **Traceable Token Vault & Local De-anonymization.**
        """)
    with r3:
        st.markdown("""
        **Cadence AI Directive 2026-R4**
        - Mandate: Zero PII transmission to external LLMs.
        - Enforcement: Reversible surrogate substitution before prompt creation.
        - Optiv Guard: **A passing scan means no matches found by the configured detector; this is not a zero-PII guarantee.**
        """)

# ==========================================
# TAB 3: Solution Architecture & Blueprint
# ==========================================
with tab3:
    st.subheader("📐 Optiv Solution Architecture & Engineering Methodology")
    st.markdown("Detailed breakdown answering all deliverables from Case Study-2 Slides 08 & 09.")

    st.markdown("### 01 & 02: Functional Design & Detailed System Architecture")
    st.markdown("""
```mermaid
flowchart TD
    subgraph Ingestion["1. Ingestion Layer"]
        A1["DOCX Files<br/>(python-docx)"]
        A2["PPTX Decks<br/>(python-pptx)"]
        A3["PDF Documents & Images<br/>(PyMuPDF / pymupdf)"]
        A4["Text / CSV<br/>(Streaming Parser)"]
    end

    subgraph Normalization["2. Structure Preservation (>=80% Structural Retention)"]
        B1["Unified Document Model<br/>(DocumentContent & ContentBlocks)"]
        B2["Layout & Context Preservation<br/>(Headings, Table Rows, Bullets, Embedded Images)"]
    end

    subgraph Detection["3. Hybrid Multi-Tier PII Detection Engine (measured against labeled cases)"]
        C1["Tier 1: Deterministic Checksums & Validation<br/>(Luhn CC, ABA Routing, SSN, PAN, Aadhaar, RFC Email)"]
        C2["Tier 2: OpenAI Privacy Filter (Local Neural 1.5B)<br/>(Bidirectional Token Classifier: Spans, Addresses, Secrets)"]
        C3["Tier 3: Cadence Contextual Heuristics<br/>(Employee IDs, Beneficiary, Underwriter Rules)"]
        C4["Tier 4: Microsoft Presidio NER<br/>(spaCy Fallback Validation)"]
        C5["Tier 5: Arbitration & False-Positive Whitelist<br/>(Priority Matrix & Span Merging)"]
        C6["Visual Intelligence Engine<br/>(PyMuPDF + QR/Barcode Scanner + Image OCR)"]
    end

    subgraph Redaction["4. Semantic Redaction & Token Vault"]
        D1["Surrogate Token Generator<br/>([PERSON_1], [US_SSN_1], [BANK_ACCOUNT_1], [SECRET_KEY_1])"]
        D2["Reversible Cryptographic Token Vault<br/>(For authorized de-anonymization)"]
        D3["Native Multi-Format Redactor<br/>(Preserves PPTX, DOCX, PDF, TXT indents, tables & images)"]
        D4["Visual Image Redactor<br/>(PyMuPDF Vector Redactions + Binary Pixel Masking)"]
    end

    subgraph Audit["5. Downstream AI & Compliance Output"]
        E1["Sanitized Prompt Payload<br/>(post-redaction detector scan)"]
        E2["Cadence Exposure Index & Audit Trail<br/>(Traceability CSV / JSON)"]
    end

    Ingestion --> Normalization
    Normalization --> Detection
    C1 --> C5
    C2 --> C5
    C3 --> C5
    C4 --> C5
    C6 --> C5
    Detection --> Redaction
    Redaction --> Audit
```
    """)

    st.divider()

    st.markdown("### 03: Extraction & Native Redaction Across Document Formats")
    st.markdown(r"""
| Format | Ingestion Engine | Native Export Redactor | Layout Preservation (Tables, Indentations, Images) |
| :--- | :--- | :--- | :--- |
| **PPTX** | `python-pptx` | `export_redacted_pptx` | Edits supported text runs in place; unsupported image/chart content is flagged and blocks verified release. |
| **DOCX** | `python-docx` | `export_redacted_docx` | Preserves paragraph runs, headings, table cells, headers/footers, and embedded pictures. |
| **PDF** | `PyMuPDF` (`pymupdf`) | `export_redacted_pdf` (`pymupdf`) | Full vector text, tables, and embedded raster images extracted; QR/barcodes decoded; visual and binary pixel redactions applied. |
| **TXT / CSV** | Native Stream Reader | `export_redacted_text` | Line-by-line whitespace, bullet indents, and CSV delimiters preserved. |
    """)

    st.divider()

    st.markdown("### 04: Reliability Metrics & False-Positive Mitigation")
    st.markdown("""
1. **Format Preservation**:
   - A structural-count proxy compares source and saved output for supported native formats. It is not a visual layout comparison; rendered-page or slide review remains necessary to establish the panel's 80% requirement.
2. **PII Detection Evaluation**:
   - Run `python evaluate_detection.py` against the reviewed seed corpus in `samples/pii_benchmark.jsonl`. It reports precision, recall, false positives, and misses; it is not evidence of 100% recall.
3. **Traceability & Explainability**:
   - Audit records retain masked values, exact character offsets, block ID, page/slide number, confidence, and source location. Raw values and surrounding context are excluded from exported audit files.
""")

# Uploaded source bytes are temporary and must not remain alongside exports.
if uploaded_file is not None and active_file_path:
    try:
        os.remove(active_file_path)
    except OSError:
        st.warning("Temporary uploaded source could not be removed from this session's temp storage.")
