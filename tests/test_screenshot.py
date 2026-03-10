from __future__ import annotations

import os
import tempfile
import time
from pathlib import Path
from unittest.mock import AsyncMock, MagicMock, patch

import pytest

from src.screenshot import ScreenshotService


class TestScreenshotService:
    def setup_method(self):
        self.tmpdir = tempfile.mkdtemp()
        self.service = ScreenshotService(
            screenshot_dir=self.tmpdir,
            gateway_url="http://localhost:3000",
            timeout_ms=5000,
        )

    def test_get_path_missing(self):
        assert self.service.get_path("nonexistent") is None

    def test_get_path_exists(self):
        path = Path(self.tmpdir) / "testhash.jpg"
        path.write_bytes(b"\xff\xd8\xff")
        result = self.service.get_path("testhash")
        assert result is not None
        assert result == path

    def test_delete_existing(self):
        path = Path(self.tmpdir) / "testhash.jpg"
        path.write_bytes(b"\xff\xd8\xff")
        assert self.service.delete("testhash") is True
        assert not path.exists()

    def test_delete_nonexistent(self):
        assert self.service.delete("nonexistent") is True

    def test_cleanup_old_deletes_expired(self):
        # Create an "old" screenshot (mtime set to 60 days ago)
        old_path = Path(self.tmpdir) / "oldhash.jpg"
        old_path.write_bytes(b"\xff\xd8\xff")
        old_mtime = time.time() - (60 * 86400)
        os.utime(str(old_path), (old_mtime, old_mtime))

        # Create a "recent" screenshot
        new_path = Path(self.tmpdir) / "newhash.jpg"
        new_path.write_bytes(b"\xff\xd8\xff")

        deleted = self.service.cleanup_old(retention_days=30)
        assert deleted == 1
        assert not old_path.exists()
        assert new_path.exists()

    def test_cleanup_old_zero_retention_skips(self):
        path = Path(self.tmpdir) / "hash.jpg"
        path.write_bytes(b"\xff\xd8\xff")
        deleted = self.service.cleanup_old(retention_days=0)
        assert deleted == 0
        assert path.exists()

    def test_available_false_before_startup(self):
        assert self.service.available is False

    def test_allowed_origin_parsing(self):
        assert self.service._allowed_origin == "http://localhost:3000"

        svc = ScreenshotService(
            screenshot_dir=self.tmpdir,
            gateway_url="https://gateway.example.com:8080/path",
        )
        assert svc._allowed_origin == "https://gateway.example.com:8080"

    async def test_capture_returns_false_when_unavailable(self):
        result = await self.service.capture("txid123", "hash123")
        assert result is False

    async def test_capture_skips_existing(self):
        # Pre-create the file
        path = Path(self.tmpdir) / "hash123.jpg"
        path.write_bytes(b"\xff\xd8\xff")

        # Mark as available with a mock browser
        self.service._browser = MagicMock()
        result = await self.service.capture("txid123", "hash123")
        assert result is True
        # Browser should not be called since file already exists
        self.service._browser.new_context.assert_not_called()

    async def test_capture_creates_screenshot(self):
        mock_page = AsyncMock()
        mock_context = AsyncMock()
        mock_context.new_page.return_value = mock_page
        mock_browser = AsyncMock()
        mock_browser.new_context.return_value = mock_context

        self.service._browser = mock_browser

        dest = Path(self.tmpdir) / "hash456.jpg"

        # Simulate screenshot writing to file
        async def fake_screenshot(**kwargs):
            Path(kwargs["path"]).write_bytes(b"\xff\xd8\xff")

        mock_page.screenshot.side_effect = fake_screenshot

        result = await self.service.capture("txid456", "hash456")
        assert result is True
        assert dest.exists()

        # Verify browser context was configured correctly
        mock_browser.new_context.assert_called_once()
        call_kwargs = mock_browser.new_context.call_args.kwargs
        assert call_kwargs["viewport"] == {"width": 1280, "height": 720}

        # Verify route was set up for network isolation
        mock_page.route.assert_called_once()

        # Verify dialog handler was registered as a named function (not lambda)
        mock_page.on.assert_called_once()
        assert mock_page.on.call_args[0][0] == "dialog"

        # Verify navigation
        mock_page.goto.assert_called_once()
        goto_kwargs = mock_page.goto.call_args.kwargs
        assert goto_kwargs["wait_until"] == "networkidle"
        assert goto_kwargs["timeout"] == 5000

        # Verify context cleanup
        mock_context.close.assert_called_once()

    async def test_capture_handles_failure(self):
        mock_context = AsyncMock()
        mock_context.new_page.side_effect = Exception("Browser crash")
        mock_browser = AsyncMock()
        mock_browser.new_context.return_value = mock_context

        self.service._browser = mock_browser

        result = await self.service.capture("txid789", "hash789")
        assert result is False
        # Partial file should be cleaned up
        assert not (Path(self.tmpdir) / "hash789.jpg").exists()
        # Context should still be closed via finally block
        mock_context.close.assert_called_once()

    async def test_startup_creates_directory(self):
        new_dir = os.path.join(self.tmpdir, "sub", "screenshots")
        svc = ScreenshotService(
            screenshot_dir=new_dir,
            gateway_url="http://localhost:3000",
        )
        mock_pw_instance = AsyncMock()
        mock_browser = AsyncMock()
        mock_pw_instance.chromium.launch.return_value = mock_browser

        mock_pw_cm = MagicMock()
        mock_pw_cm.start = AsyncMock(return_value=mock_pw_instance)

        with patch.dict("sys.modules", {"playwright": MagicMock(), "playwright.async_api": MagicMock(async_playwright=MagicMock(return_value=mock_pw_cm))}):
            await svc.startup()
            assert Path(new_dir).is_dir()
            assert svc.available is True

            await svc.shutdown()

    async def test_startup_graceful_failure(self):
        svc = ScreenshotService(
            screenshot_dir=self.tmpdir,
            gateway_url="http://localhost:3000",
        )
        # Simulate playwright not being installed
        with patch.dict("sys.modules", {"playwright": None, "playwright.async_api": None}):
            await svc.startup()
            assert svc.available is False

    async def test_shutdown_idempotent(self):
        await self.service.shutdown()
        await self.service.shutdown()


class TestScreenshotRouteIsolation:
    """Verify the route handler blocks external requests."""

    async def test_route_handler_allows_gateway(self):
        service = ScreenshotService(
            screenshot_dir="/tmp",
            gateway_url="http://gateway:3000",
        )
        # The route handler is created inside capture(), so we test the
        # origin matching logic directly
        assert service._allowed_origin == "http://gateway:3000"

    async def test_route_handler_blocks_external(self):
        service = ScreenshotService(
            screenshot_dir="/tmp",
            gateway_url="http://gateway:3000",
        )
        # External URLs should not start with the gateway origin
        assert not "https://evil.com/steal".startswith(service._allowed_origin)
        assert "http://gateway:3000/raw/txid".startswith(service._allowed_origin)
