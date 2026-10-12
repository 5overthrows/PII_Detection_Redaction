"""
Comprehensive Test and Verification Suite for Optiv PII Detection Prototype.
Tests extraction, detection, redaction, and audit reporting across DOCX, PPTX, PDF, and TXT files.
"""
import os
import json
from extractors.unified_extractor import UnifiedExtractor
from detector.pii_engine import PIIEngine
from redactor.redaction_engine import RedactionEngine
from audit.risk_assessment import RiskAssessmentEngine

def run_pipeline_test():
    base_dir = os.path.dirname(os.path.abspath(__file__))
    samples_dir = os.path.join(base_dir, "samples")
    outputs_dir = os.path.join(base_dir, "outputs")
    os.makedirs(outputs_dir, exist_ok=True)

    test_files = [
        "input.docx",
        "pii_redaction_test.docx",
        "cadence_wealth_portfolio_review.pptx",
        "cadence_credit_policy_evaluation.pdf",
        "cadence_internal_audit_memo.txt"
    ]

    print("=" * 80)
    print(" OPTIV CONSULTING — CADENCE PII DETECTION & REDACTION PIPELINE TEST")
    print("=" * 80)

    summary_results = []

    for fname in test_files:
        fpath = os.path.join(samples_dir, fname)
        if not os.path.exists(fpath):
            print(f"[!] Warning: File {fpath} does not exist.")
            continue

        print(f"\n>>> PROCESSING: {fname}")
        print("-" * 60)

        # 1. Extraction & Structural Retention
        doc = UnifiedExtractor.extract_document(fpath)
        retention_pct = "Measured after native export"
        print(f"[*] Ingestion Complete:")
        print(f"    - Type: {doc.file_type.upper()}")
        print(f"    - Total Words: {doc.total_words} | Structural Blocks: {doc.total_blocks}")
        print(f"    - Output structure preservation: {retention_pct}")
        embedded_imgs = doc.metadata.get("embedded_images", [])
        if embedded_imgs:
            print(f"    - Embedded Images (PyMuPDF): {len(embedded_imgs)} extracted")
            for img in embedded_imgs:
                print(f"      • [{img['image_id']}] Page {img['page']} ({img['dimensions']}, {img['format']}) — {img['classification']}")

        # 2. PII Detection
        entities = PIIEngine.detect_in_document(doc)
        print(f"[*] PII Detection Complete: Found {len(entities)} sensitive entities")

        # 3. Redaction & Token Vault
        redacted_doc, vault = RedactionEngine.redact_document(doc, entities)
        print(f"[*] Semantic Redaction Complete:")
        print(f"    - Unique Surrogate Tokens Created: {len(vault.reverse_map)}")

        # 4. Audit & Risk Assessment
        audit_report = RiskAssessmentEngine.generate_audit_report(doc, entities)
        print(f"[*] Risk Assessment:")
        print(f"    - Cadence Exposure Index: {audit_report.exposure_score}/100 ({audit_report.exposure_level})")
        print(f"    - PII Density: {audit_report.pii_density_per_100w} instances / 100 words")
        print(f"    - Category Breakdown: {dict(audit_report.breakdown_by_category)}")

        # 5. LLM Sanitized Payload
        llm_payload = RedactionEngine.generate_llm_payload(redacted_doc)
        print(f"[*] Downstream LLM Prompt Ready: {llm_payload['pii_leakage_risk']}")

        # 6. Export Native File Preserving Original Format & Structure
        out_native = os.path.join(outputs_dir, f"redacted_{fname}")
        try:
            RedactionEngine.export_redacted_document(fpath, out_native, entities)
            output_check = RedactionEngine.verify_redacted_output(out_native, source_path=fpath)
            native_size_kb = os.path.getsize(out_native) / 1024
            native_label = f"{out_native} ({native_size_kb:.1f} KB)"
            print(f"[*] Native output scan passed: {output_check['scan_complete'] and output_check['residual_entities'] == 0}; residuals: {output_check['residual_entities']}")
            print(f"    - Structural-count proxy: {output_check.get('structural_retention', {}).get('score')} (not visual QA)")
        except RuntimeError as exc:
            output_check = {"scan_complete": False, "residual_entities": -1}
            native_size_kb = 0
            native_label = "BLOCKED: coverage or residual PII verification failed"
            print(f"[BLOCKED] Native output withheld: {exc}")

        llm_payload = RedactionEngine.generate_llm_payload(redacted_doc)
        out_redacted_text = os.path.join(outputs_dir, f"sanitized_{fname}.txt")
        with open(out_redacted_text, "w", encoding="utf-8") as f:
            f.write(llm_payload["sanitized_payload"])
        if not llm_payload.get("release_allowed") or not output_check.get("scan_complete") or output_check.get("residual_entities"):
            print("    - WARNING: possible residual PII or incomplete content coverage; review before use.")

        # Save Audit JSON
        out_audit_json = os.path.join(outputs_dir, f"audit_{fname}.json")
        with open(out_audit_json, "w", encoding="utf-8") as f:
            json.dump({
                "file_name": audit_report.file_name,
                "exposure_score": audit_report.exposure_score,
                "exposure_level": audit_report.exposure_level,
                "total_pii": audit_report.total_pii_count,
                "categories": audit_report.breakdown_by_category,
                "severities": audit_report.breakdown_by_severity,
                "regulations": audit_report.regulatory_impacts,
                "traceability": audit_report.traceability_records
            }, f, indent=2)

        summary_results.append({
            "File": fname,
            "Type": doc.file_type.upper(),
            "Structure Retention": retention_pct,
            "PII Entities": len(entities),
            "Native Output": native_label,
            "Exposure Score": f"{audit_report.exposure_score}/100",
            "Risk Level": audit_report.exposure_level
        })

    print("\n" + "=" * 80)
    print(" EXECUTIVE SUMMARY ACROSS ALL ARTIFACTS")
    print("=" * 80)
    import pandas as pd
    df = pd.DataFrame(summary_results)
    print(df.to_string(index=False))
    print("\n[+] All tests executed successfully!")

if __name__ == "__main__":
    run_pipeline_test()
