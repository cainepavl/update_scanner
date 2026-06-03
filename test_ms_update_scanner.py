"""Tests for ms_update_scanner.py — covers categorization, merging, email body, and sending."""

import sys
import types
import unittest
from datetime import datetime
from unittest.mock import MagicMock, patch, call

# Stub config.py before importing the module so credentials are never required
sys.modules["config"] = types.SimpleNamespace(
    SMTP_SERVER="smtp.gmail.com",
    SMTP_PORT=465,
    SENDER_EMAIL="sender@test.com",
    SENDER_PASSWORD="testpass",
    RECEIVER_EMAIL="receiver@test.com",
)

import ms_update_scanner  # noqa: E402  (must come after sys.modules patch)


# ── helpers ───────────────────────────────────────────────────────────────────

def _empty_merged():
    """Return a merged dict with all categories empty (simulates a silent week)."""
    return {cat: [] for cat in ms_update_scanner.CATEGORIES}


def _make_feed(entries, bozo=False, bozo_exception=None):
    """Build a minimal feedparser-like object for mocking."""
    feed = MagicMock()
    feed.bozo = bozo
    feed.bozo_exception = bozo_exception or Exception("parse error")
    feed.entries = entries
    return feed


def _entry(title="", summary="", link="http://example.com"):
    return {"title": title, "summary": summary, "link": link}


# ── merge_results ─────────────────────────────────────────────────────────────

class TestMergeResults(unittest.TestCase):

    def test_empty_input(self):
        result = ms_update_scanner.merge_results([])
        self.assertEqual(list(result.keys()), list(ms_update_scanner.CATEGORIES.keys()))
        for items in result.values():
            self.assertEqual(items, [])

    def test_single_feed_passthrough(self):
        feed_result = _empty_merged()
        feed_result["Email Security"] = ["  * Article\n    http://x.com"]
        merged = ms_update_scanner.merge_results([feed_result])
        self.assertEqual(merged["Email Security"], ["  * Article\n    http://x.com"])

    def test_deduplication_across_feeds(self):
        article = "  * SMB Fix\n    http://x.com"
        feed1 = _empty_merged()
        feed1["Network Shares / SMB"] = [article]
        feed2 = _empty_merged()
        feed2["Network Shares / SMB"] = [article]
        merged = ms_update_scanner.merge_results([feed1, feed2])
        self.assertEqual(merged["Network Shares / SMB"], [article])

    def test_different_articles_both_present(self):
        a1 = "  * Article One\n    http://a.com"
        a2 = "  * Article Two\n    http://b.com"
        feed1 = _empty_merged()
        feed1["Email Security"] = [a1]
        feed2 = _empty_merged()
        feed2["Email Security"] = [a2]
        merged = ms_update_scanner.merge_results([feed1, feed2])
        self.assertIn(a1, merged["Email Security"])
        self.assertIn(a2, merged["Email Security"])

    def test_preserves_category_keys(self):
        merged = ms_update_scanner.merge_results([_empty_merged()])
        self.assertEqual(set(merged.keys()), set(ms_update_scanner.CATEGORIES.keys()))

    def test_deduplication_preserves_order(self):
        a, b, c = "  * A\n    u", "  * B\n    v", "  * C\n    w"
        feed1 = _empty_merged()
        feed1["MS Access"] = [a, b]
        feed2 = _empty_merged()
        feed2["MS Access"] = [b, c]
        merged = ms_update_scanner.merge_results([feed1, feed2])
        self.assertEqual(merged["MS Access"], [a, b, c])


# ── build_email_body ──────────────────────────────────────────────────────────

class TestBuildEmailBody(unittest.TestCase):

    def test_all_empty_returns_no_hits(self):
        _, any_hits = ms_update_scanner.build_email_body(_empty_merged())
        self.assertFalse(any_hits)

    def test_with_matches_returns_any_hits_true(self):
        merged = _empty_merged()
        merged["Email Security"] = ["  * Outlook change\n    http://x.com"]
        _, any_hits = ms_update_scanner.build_email_body(merged)
        self.assertTrue(any_hits)

    def test_body_contains_date(self):
        today = datetime.now().strftime("%Y-%m-%d")
        body, _ = ms_update_scanner.build_email_body(_empty_merged())
        self.assertIn(today, body)

    def test_category_names_uppercase_in_body(self):
        body, _ = ms_update_scanner.build_email_body(_empty_merged())
        for cat in ms_update_scanner.CATEGORIES:
            self.assertIn(cat.upper(), body)

    def test_empty_category_shows_placeholder(self):
        body, _ = ms_update_scanner.build_email_body(_empty_merged())
        self.assertIn("No matching updates this week", body)

    def test_matched_articles_appear_in_body(self):
        merged = _empty_merged()
        merged["Network Shares / SMB"] = ["  * SMB Fix\n    http://example.com/smb"]
        body, _ = ms_update_scanner.build_email_body(merged)
        self.assertIn("SMB Fix", body)
        self.assertIn("http://example.com/smb", body)

    def test_returns_string_and_bool(self):
        result = ms_update_scanner.build_email_body(_empty_merged())
        self.assertIsInstance(result[0], str)
        self.assertIsInstance(result[1], bool)


# ── fetch_and_categorize ──────────────────────────────────────────────────────

class TestFetchAndCategorize(unittest.TestCase):

    def _fetch(self, entries, bozo=False):
        feed = _make_feed(entries, bozo=bozo)
        with patch("feedparser.parse", return_value=feed):
            return ms_update_scanner.fetch_and_categorize("http://feed.url", "Test Feed")

    def test_match_in_title(self):
        result = self._fetch([_entry(title="SMB Protocol Changes", summary="")])
        self.assertTrue(len(result["Network Shares / SMB"]) > 0)

    def test_match_in_summary(self):
        result = self._fetch([_entry(title="Weekly Digest", summary="Outlook SMTP config changes")])
        self.assertTrue(len(result["Email Security"]) > 0)

    def test_case_insensitive_match(self):
        # Keyword "smb" should match uppercase "SMB" in the title
        result = self._fetch([_entry(title="Critical SMB VULNERABILITY", summary="")])
        self.assertTrue(len(result["Network Shares / SMB"]) > 0)

    def test_article_matches_multiple_categories(self):
        result = self._fetch([_entry(title="Exchange Server SMB Update", summary="")])
        self.assertTrue(len(result["Email Security"]) > 0)
        self.assertTrue(len(result["Network Shares / SMB"]) > 0)

    def test_irrelevant_article_no_matches(self):
        result = self._fetch([_entry(title="Coffee Machine Firmware", summary="Hot beverages")])
        for items in result.values():
            self.assertEqual(items, [])

    def test_bozo_with_no_entries_returns_empty_dict(self):
        feed = _make_feed([], bozo=True)
        with patch("feedparser.parse", return_value=feed):
            result = ms_update_scanner.fetch_and_categorize("http://feed.url", "Bad Feed")
        self.assertEqual(result, {})

    def test_bozo_with_entries_still_processes(self):
        # A technically malformed feed that still yields entries should not be dropped
        result = self._fetch([_entry(title="SMB regression", summary="")], bozo=True)
        self.assertNotEqual(result, {})
        self.assertTrue(len(result["Network Shares / SMB"]) > 0)

    def test_exception_during_parse_returns_empty_dict(self):
        with patch("feedparser.parse", side_effect=Exception("network error")):
            result = ms_update_scanner.fetch_and_categorize("http://feed.url", "Broken Feed")
        self.assertEqual(result, {})

    def test_result_has_all_category_keys(self):
        result = self._fetch([])
        self.assertEqual(set(result.keys()), set(ms_update_scanner.CATEGORIES.keys()))

    def test_article_formatted_with_title_and_link(self):
        result = self._fetch([_entry(title="SMB Fix", summary="", link="http://fix.com")])
        items = result["Network Shares / SMB"]
        self.assertEqual(len(items), 1)
        self.assertIn("SMB Fix", items[0])
        self.assertIn("http://fix.com", items[0])

    def test_empty_feed_returns_all_empty_lists(self):
        result = self._fetch([])
        for items in result.values():
            self.assertEqual(items, [])


# ── send_summary ──────────────────────────────────────────────────────────────

class TestSendSummary(unittest.TestCase):

    def _send(self, body="Test email body"):
        with patch("smtplib.SMTP_SSL") as MockSMTP:
            mock_server = MagicMock()
            MockSMTP.return_value.__enter__.return_value = mock_server
            MockSMTP.return_value.__exit__.return_value = False
            ms_update_scanner.send_summary(body)
            return MockSMTP, mock_server

    def test_smtp_called_with_correct_server_and_port(self):
        MockSMTP, _ = self._send()
        args, kwargs = MockSMTP.call_args
        self.assertEqual(args[0], "smtp.gmail.com")
        self.assertEqual(args[1], 465)

    def test_login_called_with_credentials(self):
        _, server = self._send()
        server.login.assert_called_once_with("sender@test.com", "testpass")

    def test_send_message_called(self):
        _, server = self._send()
        server.send_message.assert_called_once()

    def test_email_has_correct_from_and_to(self):
        _, server = self._send()
        msg = server.send_message.call_args[0][0]
        self.assertEqual(msg["From"], "sender@test.com")
        self.assertEqual(msg["To"], "receiver@test.com")

    def test_subject_contains_date(self):
        _, server = self._send()
        msg = server.send_message.call_args[0][0]
        today = datetime.now().strftime("%Y-%m-%d")
        self.assertIn(today, msg["Subject"])

    def test_body_content_included(self):
        _, server = self._send(body="Important update info")
        msg = server.send_message.call_args[0][0]
        self.assertIn("Important update info", msg.get_content())


if __name__ == "__main__":
    unittest.main(verbosity=2)
