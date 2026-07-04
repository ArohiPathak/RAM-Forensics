"""
Test suite for PDF Generator module

Tests cover:
- Metadata validation
- PDF generation with valid inputs
- Error handling for invalid inputs
- File creation and verification
"""

import os
import sys
import tempfile
import unittest
from pathlib import Path

# Add project root to path
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from reports.pdf_generator import PDFGenerator, generate_forensic_pdf, _validate_inputs


class TestPDFGeneratorValidation(unittest.TestCase):
    """Test input validation.

    NOTE: `_validate_inputs` lives as a module-level function in
    reports/pdf_generator.py (it doesn't need `self`, so it isn't a method
    on PDFGenerator anymore). These tests call it directly rather than
    through `generator._validate_inputs(...)`.
    """

    def setUp(self):
        """Set up test fixtures."""
        self.generator = PDFGenerator()
        self.valid_metadata = {
            "Case ID": "CASE-2026-001",
            "Lead Investigator": "Analyst Team",
            "Target File": "C:\\Dumps\\mem.raw",
            "Profile": "Win10x64_19041",
            "Risk Score": "82/100",
            "Report Date": "2026-07-01 16:40:12"
        }
        self.valid_findings = [
            "Cobalt Strike C2 Beacon detected in nc.exe PID 4096",
            "Process Hollowing signature in svchost.exe PID 3244"
        ]
        self.valid_recommendations = [
            "Isolate endpoint immediately",
            "Terminate malicious processes"
        ]

    def test_valid_inputs(self):
        """Test that validation passes with valid inputs."""
        # Should not raise
        _validate_inputs(
            self.valid_metadata,
            self.valid_findings,
            self.valid_recommendations
        )

    def test_missing_metadata_key(self):
        """Test validation fails with missing metadata key."""
        incomplete_metadata = {k: v for k, v in self.valid_metadata.items() if k != "Case ID"}

        with self.assertRaises(ValueError) as cm:
            _validate_inputs(
                incomplete_metadata,
                self.valid_findings,
                self.valid_recommendations
            )
        self.assertIn("Missing required metadata key", str(cm.exception))

    def test_empty_findings(self):
        """Test validation fails with empty findings."""
        with self.assertRaises(ValueError) as cm:
            _validate_inputs(
                self.valid_metadata,
                [],
                self.valid_recommendations
            )
        self.assertIn("Findings must be a non-empty list", str(cm.exception))

    def test_empty_recommendations(self):
        """Test validation fails with empty recommendations."""
        with self.assertRaises(ValueError) as cm:
            _validate_inputs(
                self.valid_metadata,
                self.valid_findings,
                []
            )
        self.assertIn("Recommendations must be a non-empty list", str(cm.exception))

    def test_findings_not_list(self):
        """Test validation fails if findings is not a list."""
        with self.assertRaises(ValueError):
            _validate_inputs(
                self.valid_metadata,
                "not a list",
                self.valid_recommendations
            )

    def test_recommendations_not_list(self):
        """Test validation fails if recommendations is not a list."""
        with self.assertRaises(ValueError):
            _validate_inputs(
                self.valid_metadata,
                self.valid_findings,
                "not a list"
            )


class TestPDFGeneration(unittest.TestCase):
    """Test PDF generation functionality."""

    def setUp(self):
        """Set up test fixtures."""
        self.temp_dir = tempfile.mkdtemp()
        self.output_path = os.path.join(self.temp_dir, "test_report.pdf")

        self.metadata = {
            "Case ID": "CASE-2026-001",
            "Lead Investigator": "Analyst Team",
            "Target File": "C:\\Dumps\\mem.raw",
            "Profile": "Win10x64_19041",
            "Risk Score": "82/100",
            "Report Date": "2026-07-01 16:40:12"
        }
        self.findings = [
            "Cobalt Strike C2 Beacon detected in processes space nc.exe PID 4096.",
            "Process Hollowing signature flagged in host svchost.exe PID 3244 VAD maps.",
            "Active outbound TCP socket tunnel open to command server 185.112.144.5:4444.",
            "Anomalous dynamic link library unknown_inject.dll loaded out of public profile paths."
        ]
        self.recommendations = [
            "Isolate the target endpoint from net ingress/egress immediately to stop exfiltration.",
            "Terminate malicious PIDs (4096, 3244, 5120) and purge public folders.",
            "Revoke compromised analyst credentials, session hashes, and local domain tokens."
        ]

    def tearDown(self):
        """Clean up test files."""
        if os.path.exists(self.temp_dir):
            import shutil
            shutil.rmtree(self.temp_dir)

    def test_pdf_generation_with_raw_pdf(self):
        """Test PDF generation with raw PDF method (the no-dependency fallback)."""
        generator = PDFGenerator()
        result_path = generator._generate_with_raw_pdf(
            self.output_path,
            self.metadata,
            self.findings,
            self.recommendations
        )

        # Verify file was created
        self.assertTrue(os.path.exists(result_path))

        # Verify file has content
        file_size = os.path.getsize(result_path)
        self.assertGreater(file_size, 100, "PDF file should have substantial size")

        # Verify PDF header
        with open(result_path, 'rb') as f:
            header = f.read(4)
            self.assertEqual(header, b'%PDF', "PDF should start with %PDF header")

    def test_pdf_generation_public_api(self):
        """Test PDF generation using public API."""
        result_path = generate_forensic_pdf(
            self.output_path,
            self.metadata,
            self.findings,
            self.recommendations
        )

        # Verify file was created
        self.assertTrue(os.path.exists(result_path))

        # Verify absolute path returned
        self.assertTrue(os.path.isabs(result_path))

        # Verify file size
        file_size = os.path.getsize(result_path)
        self.assertGreater(file_size, 100)

    def test_pdf_contains_metadata(self):
        """Test that PDF contains metadata."""
        generator = PDFGenerator()
        generator._generate_with_raw_pdf(
            self.output_path,
            self.metadata,
            self.findings,
            self.recommendations
        )

        # Read PDF content
        with open(self.output_path, 'rb') as f:
            content = f.read()

        # Check for presence of key PDF structure indicators
        self.assertIn(b'stream', content, "PDF should contain stream objects")
        self.assertIn(b'endobj', content, "PDF should contain proper object structure")

    def test_directory_creation(self):
        """Test that missing directories are created."""
        nested_path = os.path.join(self.temp_dir, "nested", "deep", "path", "report.pdf")

        result_path = generate_forensic_pdf(
            nested_path,
            self.metadata,
            self.findings,
            self.recommendations
        )

        # Verify directories were created
        self.assertTrue(os.path.exists(os.path.dirname(result_path)))
        self.assertTrue(os.path.exists(result_path))

    def test_long_metadata_values(self):
        """Test handling of very long metadata values."""
        long_metadata = self.metadata.copy()
        long_metadata["Target File"] = "C:\\" + "very" * 100 + "\\long\\path\\to\\memory\\dump.raw"

        result_path = generate_forensic_pdf(
            self.output_path,
            long_metadata,
            self.findings,
            self.recommendations
        )

        self.assertTrue(os.path.exists(result_path))
        file_size = os.path.getsize(result_path)
        self.assertGreater(file_size, 100)

    def test_special_characters_in_findings(self):
        """Test handling of special characters in findings."""
        special_findings = [
            "Process with parentheses (svchost.exe) detected",
            "Backslash path: C:\\Windows\\System32\\test.exe",
            "Quotes and apostrophes: O'Malley's process",
            "Mathematical symbols: < > <= >= & |"
        ]

        result_path = generate_forensic_pdf(
            self.output_path,
            self.metadata,
            special_findings,
            self.recommendations
        )

        self.assertTrue(os.path.exists(result_path))
        file_size = os.path.getsize(result_path)
        self.assertGreater(file_size, 100)

    def test_multiple_findings_and_recommendations(self):
        """Test handling of many findings and recommendations."""
        many_findings = [f"Finding #{i}: Suspicious activity detected at address 0x{i:08X}"
                        for i in range(20)]
        many_recommendations = [f"Recommendation #{i}: Take action on item {i}"
                               for i in range(15)]

        result_path = generate_forensic_pdf(
            self.output_path,
            self.metadata,
            many_findings,
            many_recommendations
        )

        self.assertTrue(os.path.exists(result_path))
        file_size = os.path.getsize(result_path)
        self.assertGreater(file_size, 100)


class TestRiskAssessmentBreakdown(unittest.TestCase):
    """Test the optional detection-category breakdown table.

    This covers the new `detection_details` parameter added to
    generate_forensic_pdf(). It's optional, so we test both the
    "provided" and "omitted" cases to make sure neither one breaks
    generation.
    """

    def setUp(self):
        """Set up test fixtures."""
        self.temp_dir = tempfile.mkdtemp()
        self.output_path = os.path.join(self.temp_dir, "test_report.pdf")

        self.metadata = {
            "Case ID": "CASE-2026-001",
            "Lead Investigator": "Analyst Team",
            "Target File": "C:\\Dumps\\mem.raw",
            "Profile": "Win10x64_19041",
            "Risk Score": "82/100 (HIGH LEVEL)",
            "Report Date": "2026-07-01 16:40:12"
        }
        self.findings = ["Hidden process detected"]
        self.recommendations = ["Isolate endpoint"]

    def tearDown(self):
        """Clean up test files."""
        if os.path.exists(self.temp_dir):
            import shutil
            shutil.rmtree(self.temp_dir)

    def test_generation_without_detection_details(self):
        """detection_details is optional; omitting it should still work."""
        result_path = generate_forensic_pdf(
            self.output_path,
            self.metadata,
            self.findings,
            self.recommendations
        )
        self.assertTrue(os.path.exists(result_path))

    def test_generation_with_detection_details(self):
        """Passing a populated detection_details dict should still work."""
        detection_details = {
            "hidden_processes": ["svchost_fake.exe"],
            "unknown_dlls": [],
            "external_connections": ["185.112.144.5:4444"],
            "powershell_activity": [],
        }
        result_path = generate_forensic_pdf(
            self.output_path,
            self.metadata,
            self.findings,
            self.recommendations,
            detection_details=detection_details
        )
        self.assertTrue(os.path.exists(result_path))
        file_size = os.path.getsize(result_path)
        self.assertGreater(file_size, 100)

    def test_generation_with_empty_detection_details(self):
        """A detection_details dict with no hits in any category shouldn't crash."""
        detection_details = {
            "hidden_processes": [],
            "unknown_dlls": [],
            "external_connections": [],
            "powershell_activity": [],
        }
        result_path = generate_forensic_pdf(
            self.output_path,
            self.metadata,
            self.findings,
            self.recommendations,
            detection_details=detection_details
        )
        self.assertTrue(os.path.exists(result_path))


class TestPDFStructure(unittest.TestCase):
    """Test PDF structure and compliance."""

    def setUp(self):
        """Set up test fixtures."""
        self.temp_dir = tempfile.mkdtemp()
        self.output_path = os.path.join(self.temp_dir, "test_report.pdf")

        self.metadata = {
            "Case ID": "CASE-2026-001",
            "Lead Investigator": "Analyst Team",
            "Target File": "C:\\Dumps\\mem.raw",
            "Profile": "Win10x64_19041",
            "Risk Score": "82/100",
            "Report Date": "2026-07-01 16:40:12"
        }
        self.findings = ["Test finding"]
        self.recommendations = ["Test recommendation"]

    def tearDown(self):
        """Clean up test files."""
        if os.path.exists(self.temp_dir):
            import shutil
            shutil.rmtree(self.temp_dir)

    def test_pdf_header(self):
        """Test PDF file starts with proper header."""
        generate_forensic_pdf(
            self.output_path,
            self.metadata,
            self.findings,
            self.recommendations
        )

        with open(self.output_path, 'rb') as f:
            header = f.read(8)
            self.assertEqual(header, b'%PDF-1.4', "PDF should start with %PDF-1.4")

    def test_pdf_footer(self):
        """Test PDF file ends with proper footer."""
        generate_forensic_pdf(
            self.output_path,
            self.metadata,
            self.findings,
            self.recommendations
        )

        with open(self.output_path, 'rb') as f:
            f.seek(-10, 2)  # Seek to 10 bytes before end
            footer = f.read()
            self.assertIn(b'%%EOF', footer, "PDF should end with %%EOF")

    def test_pdf_objects_present(self):
        """Test PDF contains required objects."""
        generate_forensic_pdf(
            self.output_path,
            self.metadata,
            self.findings,
            self.recommendations
        )

        with open(self.output_path, 'rb') as f:
            content = f.read()

        # Check for required PDF structures
        self.assertIn(b'obj', content, "PDF should contain objects")
        self.assertIn(b'endobj', content, "PDF should contain endobj markers")
        self.assertIn(b'stream', content, "PDF should contain stream objects")
        self.assertIn(b'endstream', content, "PDF should contain endstream markers")
        self.assertIn(b'xref', content, "PDF should contain xref table")
        self.assertIn(b'trailer', content, "PDF should contain trailer")

    def test_pdf_can_be_read(self):
        """Test that generated PDF is readable."""
        generate_forensic_pdf(
            self.output_path,
            self.metadata,
            self.findings,
            self.recommendations
        )

        # Should be able to open and read the file
        try:
            with open(self.output_path, 'rb') as f:
                content = f.read()
                self.assertGreater(len(content), 100)
        except Exception as e:
            self.fail(f"PDF file could not be read: {e}")


class TestIntegration(unittest.TestCase):
    """Integration tests with real-world data."""

    def setUp(self):
        """Set up test fixtures."""
        self.temp_dir = tempfile.mkdtemp()
        self.output_path = os.path.join(self.temp_dir, "forensic_report.pdf")

    def tearDown(self):
        """Clean up test files."""
        if os.path.exists(self.temp_dir):
            import shutil
            shutil.rmtree(self.temp_dir)

    def test_real_world_report(self):
        """Test generation of realistic forensic report."""
        metadata = {
            "Case ID": "CASE-2026-004",
            "Lead Investigator": "Cyber Analyst Team 404",
            "Target File": "C:\\Forensics\\dumps\\mem_dump_cybersecurity_incident.raw",
            "Profile": "Win10x64_19041 (Windows 10 Pro)",
            "Risk Score": "82/100 (CRITICAL LEVEL)",
            "Report Date": "2026-07-01 16:40:12"
        }

        findings = [
            "Cobalt Strike C2 Beacon detected in processes space nc.exe PID 4096.",
            "Process Hollowing signature flagged in host svchost.exe PID 3244 VAD maps.",
            "Active outbound TCP socket tunnel open to command server 185.112.144.5:4444.",
            "Anomalous dynamic link library unknown_inject.dll loaded out of public profile paths.",
            "PowerShell execution with base64-encoded command detected in PID 5120.",
            "Credential theft indicators: LSASS memory dump attempt detected."
        ]

        recommendations = [
            "Isolate the target endpoint from net ingress/egress immediately to stop exfiltration.",
            "Terminate malicious PIDs (4096, 3244, 5120) and purge public folders.",
            "Revoke compromised analyst credentials, session hashes, and local domain tokens.",
            "Scan all network-connected systems for indicators of compromise (C2 communications).",
            "Enable endpoint detection and response (EDR) on all systems in the environment.",
            "Review firewall logs for similar outbound connections to 185.112.144.5:4444."
        ]

        detection_details = {
            "hidden_processes": [],
            "unknown_dlls": ["unknown_inject.dll"],
            "external_connections": ["185.112.144.5:4444"],
            "powershell_activity": ["PID 5120"],
        }

        result_path = generate_forensic_pdf(
            self.output_path,
            metadata,
            findings,
            recommendations,
            detection_details=detection_details
        )

        # Verify success
        self.assertTrue(os.path.exists(result_path))

        # Verify file size is reasonable
        file_size = os.path.getsize(result_path)
        self.assertGreater(file_size, 500, "Report should have substantial content")
        self.assertLess(file_size, 10_000_000, "Report should be reasonably sized")

        print(f"\n✓ Real-world report generated: {result_path}")
        print(f"  File size: {file_size} bytes")


def run_tests(verbosity=2):
    """Run all tests and return results."""
    # Create test suite
    loader = unittest.TestLoader()
    suite = unittest.TestSuite()

    # Add all test classes
    suite.addTests(loader.loadTestsFromTestCase(TestPDFGeneratorValidation))
    suite.addTests(loader.loadTestsFromTestCase(TestPDFGeneration))
    suite.addTests(loader.loadTestsFromTestCase(TestRiskAssessmentBreakdown))
    suite.addTests(loader.loadTestsFromTestCase(TestPDFStructure))
    suite.addTests(loader.loadTestsFromTestCase(TestIntegration))

    # Run tests
    runner = unittest.TextTestRunner(verbosity=verbosity)
    result = runner.run(suite)

    return result


if __name__ == "__main__":
    print("=" * 70)
    print("RAM Forensics PDF Generator - Test Suite")
    print("=" * 70)

    result = run_tests(verbosity=2)

    print("\n" + "=" * 70)
    print("Test Summary")
    print("=" * 70)
    print(f"Tests run: {result.testsRun}")
    print(f"Successes: {result.testsRun - len(result.failures) - len(result.errors)}")
    print(f"Failures: {len(result.failures)}")
    print(f"Errors: {len(result.errors)}")
    print("=" * 70)

    # Exit with appropriate code
    sys.exit(0 if result.wasSuccessful() else 1)