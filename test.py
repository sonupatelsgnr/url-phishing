import unittest
from app import app
from feature_extractor import extract_features


class TestPhishingDetection(unittest.TestCase):

    def setUp(self):
        """Set up Flask test client."""
        self.app = app.test_client()
        self.app.testing = True

    def test_feature_extractor(self):
        """Verify feature extractor correctly outputs 19 numerical features."""
        features = extract_features("https://www.google.com")
        self.assertEqual(len(features), 19)
        self.assertTrue(all(isinstance(x, (int, float)) for x in features))

    def test_analyze_endpoint_trusted(self):
        """Verify whitelisted trusted domains return correct low-risk scores."""
        response = self.app.post('/analyze', json={"url": "https://www.google.com"})
        data = response.get_json()
        self.assertEqual(response.status_code, 200)
        self.assertTrue(data["success"])
        self.assertEqual(data["prediction"], "Legitimate")
        self.assertEqual(data["risk_level"], "Safe")
        self.assertEqual(data["risk_percent"], 2)
        self.assertIn("Trusted Whitelist", [c["label"] for c in data["checks"]])

    def test_analyze_endpoint_suspicious(self):
        """Verify suspicious URL structures trigger risk adjustments."""
        response = self.app.post(
            '/analyze', 
            json={"url": "http://192.168.1.1/admin/login.php?redirect=paypal"}
        )
        data = response.get_json()
        self.assertEqual(response.status_code, 200)
        self.assertTrue(data["success"])
        self.assertIn(data["prediction"], ["Suspicious", "Phishing"])
        self.assertTrue(len(data["checks"]) > 0)
        # Check that IP Address Usage is caught
        self.assertIn("IP Address Usage", [c["label"] for c in data["checks"]])

    def test_analyze_endpoint_invalid(self):
        """Verify input validation and error states return 400 Bad Request."""
        # Empty input
        response = self.app.post('/analyze', json={"url": ""})
        self.assertEqual(response.status_code, 400)
        self.assertFalse(response.get_json()["success"])

        # Invalid format input
        response = self.app.post('/analyze', json={"url": "not-a-valid-url"})
        self.assertEqual(response.status_code, 400)
        self.assertFalse(response.get_json()["success"])


if __name__ == "__main__":
    unittest.main()