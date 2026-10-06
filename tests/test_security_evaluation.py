import json

from cipherchat.security.evaluation import main, run_evaluation, write_jsonl, write_markdown


def test_preliminary_security_evaluation_documents_every_required_property():
    report = run_evaluation(sample_size=12)
    by_property = {result.security_property: result for result in report.results}

    assert set(by_property) == {
        "Confidentiality", "Authenticity", "Integrity", "Non-repudiation",
        "Evidence tampering", "Access control",
    }
    assert by_property["Confidentiality"].metrics["wrong_key_rejection_rate"] == 1.0
    assert by_property["Authenticity"].metrics["forgery_rejection_rate"] == 1.0
    assert by_property["Integrity"].metrics["tamper_detection_rate"] == 1.0
    assert by_property["Evidence tampering"].metrics["tampering_detection_rate"] == 1.0
    assert by_property["Access control"].metrics["unauthorized_rejection_rate"] == 1.0

    # A shared-key MAC cannot support non-repudiation; the evaluator must not
    # accidentally present this missing property as a passed guarantee.
    assert by_property["Non-repudiation"].status == "LIMITATION"
    assert by_property["Non-repudiation"].metrics["peer_forgery_accepted"] is True
    assert report.overall_status == "PASS WITH LIMITATIONS"


def test_evaluation_writes_interpretable_markdown_and_one_json_log_per_case(tmp_path):
    report = run_evaluation(sample_size=3)
    jsonl = tmp_path / "security_evaluation.jsonl"
    markdown = tmp_path / "SECURITY_TEST_REPORT.md"

    write_jsonl(report, jsonl)
    write_markdown(report, markdown, jsonl.name)

    records = [json.loads(line) for line in jsonl.read_text().splitlines()]
    assert len(records) == len(report.results) == 6
    assert all({"case_id", "status", "metrics", "interpretation"} <= record.keys() for record in records)
    assert all("plaintext" not in record and "session_key" not in record for record in records)

    text = markdown.read_text()
    assert "PASS WITH LIMITATIONS" in text
    assert "Non-repudiation" in text
    assert "does **not** provide non-repudiation" in text


def test_single_cli_command_prints_a_self_contained_evaluator_report(tmp_path, capsys):
    exit_code = main(["--sample-size", "3", "--output-dir", str(tmp_path)])
    output = capsys.readouterr().out

    assert exit_code == 0
    assert "CIPHERCHAT PRELIMINARY INFORMATION-SECURITY EVALUATION" in output
    assert "WHAT IS TESTED" in output
    assert "EXPECTED" in output
    assert "OBSERVED" in output
    assert "METRICS" in output
    assert "MEANING" in output
    assert "FINAL SECURITY POSTURE" in output
    assert "PASS WITH LIMITATIONS" in output
    assert "JSONL AUDIT LOG" in output
