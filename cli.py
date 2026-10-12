"""
Command-Line Interface (CLI) for Optiv PII Detection & Redaction Gateway.
Enables automated headless batch processing and audit generation.
"""
import argparse
import os
import json
from extractors.unified_extractor import UnifiedExtractor
from detector.pii_engine import PIIEngine
from redactor.redaction_engine import RedactionEngine
from audit.risk_assessment import RiskAssessmentEngine

def main():
    parser = argparse.ArgumentParser(description="Optiv PII Detection Gateway for Cadence Financial Services")
    parser.add_argument("--file", "-f", help="Path to input artifact (.docx, .pptx, .pdf, .txt, .csv)", required=True)
    parser.add_argument("--outdir", "-o", help="Directory to save outputs", default="outputs")
    parser.add_argument("--verbose", "-v", action="store_true", help="Print detailed entity list")

    args = parser.parse_args()
    file_path = args.file
    out_dir = args.outdir
    os.makedirs(out_dir, exist_ok=True)

    if not os.path.exists(file_path):
        print(f"Error: File not found: {file_path}")
        return

    fname = os.path.basename(file_path)
    print(f"[*] Ingesting: {fname}")
    doc = UnifiedExtractor.extract_document(file_path)
    print(f"    - Type: {doc.file_type.upper()} | Words: {doc.total_words}")
    print("    - Output structure preservation: measured after native export")
    images_summary = doc.metadata.get("embedded_images", [])
    if images_summary:
        barcodes_cnt = sum(img.get("barcode_count", 0) for img in images_summary)
        pii_imgs = sum(1 for img in images_summary if img.get("has_pii"))
        print(f"    - Embedded Images (PyMuPDF): {len(images_summary)} extracted | {barcodes_cnt} barcodes/QRs decoded | {pii_imgs} with PII")
    for warning in doc.metadata.get("coverage", {}).get("warnings", []):
        print(f"    - COVERAGE NOTICE: {warning}")

    print(f"[*] Executing Multi-Tier PII Detection Engine...")
    entities = PIIEngine.detect_in_document(doc)
    print(f"    - Detected {len(entities)} sensitive PII entities")

    print(f"[*] Redacting & Generating Surrogate Vault...")
    redacted_doc, vault = RedactionEngine.redact_document(doc, entities)
    print(f"    - Generated {len(vault.reverse_map)} surrogate tokens")

    print(f"[*] Evaluating Cadence Exposure Risk & Regulatory Impact...")
    audit_report = RiskAssessmentEngine.generate_audit_report(doc, entities)
    print(f"    - Cadence Exposure Score: {audit_report.exposure_score}/100 ({audit_report.exposure_level})")
    print(f"    - PII Density: {audit_report.pii_density_per_100w} instances / 100 words")

    if args.verbose:
        print("\n--- Detected Entities ---")
        for e in entities:
            print(f"  [{e.severity}] {e.entity_type} -> '[REDACTED]' => {e.surrogate_token} (Confidence: {int(e.confidence*100)}%)")

    # Export
    llm_payload = RedactionEngine.generate_llm_payload(redacted_doc)

    audit_json_path = os.path.join(out_dir, f"audit_{fname}.json")
    with open(audit_json_path, "w", encoding="utf-8") as f:
        json.dump({
            "file": fname,
            "exposure_score": audit_report.exposure_score,
            "exposure_level": audit_report.exposure_level,
            "total_pii": audit_report.total_pii_count,
            "categories": audit_report.breakdown_by_category,
            "severities": audit_report.breakdown_by_severity,
            "traceability": audit_report.traceability_records
        }, f, indent=2)

    # Native format-preserving redaction export
    out_native_path = os.path.join(out_dir, f"redacted_{fname}")
    try:
        RedactionEngine.export_redacted_document(file_path, out_native_path, entities)
    except RuntimeError as exc:
        print(f"[BLOCKED] Native output withheld: {exc}")
        return
    output_check = RedactionEngine.verify_redacted_output(out_native_path, source_path=file_path)
    print(f"    - Exported Native Redacted File ({doc.file_type.upper()}): {out_native_path}")
    print(f"      - Configured-detector re-scan complete: {output_check['scan_complete']}; residual entities: {output_check['residual_entities']}")
    print(f"      - Structural-count proxy: {output_check.get('structural_retention', {}).get('score')} (not a visual layout score)")
    for warning in output_check.get("warnings", []):
        print(f"      - COVERAGE WARNING: {warning}")

    sanitized_txt_path = os.path.join(out_dir, f"sanitized_{fname}.txt")
    with open(sanitized_txt_path, "w", encoding="utf-8") as f:
        f.write(llm_payload["sanitized_payload"])
    if not llm_payload.get("release_allowed") or not output_check.get("scan_complete") or output_check.get("residual_entities"):
        print("      - WARNING: possible residual PII or incomplete content coverage; review before use.")

    print("    - Plaintext token vault export withheld; it contains original PII.")

    print(f"[+] Processing completed successfully. Outputs written to: {out_dir}")

if __name__ == "__main__":
    main()
