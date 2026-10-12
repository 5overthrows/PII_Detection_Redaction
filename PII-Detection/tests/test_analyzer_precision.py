from __future__ import annotations

import sys
import unittest
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import Mock, patch

PROJECT_ROOT = Path(__file__).resolve().parents[1]
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

from backend.analyzer import PII_ENTITIES, _SCORE_THRESHOLD, analyze


class AnalyzerPrecisionTests(unittest.TestCase):
    def test_generic_office_location_is_not_redacted(self) -> None:
        text = "Quarterly results for the New York Office"
        location = SimpleNamespace(
            entity_type="LOCATION", start=text.index("New York"), score=0.99
        )
        analyzer = Mock()
        analyzer.analyze.return_value = [location]

        with patch("backend.analyzer.get_analyzer", return_value=analyzer):
            results = analyze(text)

        self.assertEqual(results, [])

    def test_address_and_birth_date_require_explicit_labels(self) -> None:
        address_text = "Customer address: 18 Lake Road"
        address = SimpleNamespace(
            entity_type="LOCATION",
            start=address_text.index("Lake Road"),
            score=0.99,
        )
        birth_text = "Date of birth: December 2, 1990"
        birth_date = SimpleNamespace(
            entity_type="DATE_TIME",
            start=birth_text.index("December"),
            score=0.99,
        )
        analyzer = Mock()
        analyzer.analyze.side_effect = ([address], [birth_date])

        with patch("backend.analyzer.get_analyzer", return_value=analyzer):
            address_results = analyze(address_text)
            birth_results = analyze(birth_text)

        self.assertEqual(address_results, [address])
        self.assertEqual(birth_results, [birth_date])

    def test_detector_uses_higher_confidence_and_specific_entity_set(self) -> None:
        analyzer = Mock()
        analyzer.analyze.return_value = []
        with patch("backend.analyzer.get_analyzer", return_value=analyzer):
            analyze("contact test@example.com")

        analyzer.analyze.assert_called_once_with(
            text="contact test@example.com",
            language="en",
            entities=PII_ENTITIES,
            score_threshold=_SCORE_THRESHOLD,
        )
        self.assertEqual(_SCORE_THRESHOLD, 0.5)
        self.assertNotIn("URL", PII_ENTITIES)
        self.assertNotIn("DOMAIN_NAME", PII_ENTITIES)
        self.assertNotIn("NRP", PII_ENTITIES)


if __name__ == "__main__":
    unittest.main()
