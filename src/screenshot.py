from __future__ import annotations

import logging
from pathlib import Path
from urllib.parse import urlparse

logger = logging.getLogger("scanner.screenshot")


class ScreenshotService:
    """Captures screenshots of flagged content using a headless browser.

    Uses Playwright to render pages in an isolated browser context.
    Only gateway-origin requests are allowed; all external network
    requests are blocked for security.
    """

    def __init__(
        self,
        screenshot_dir: str,
        gateway_url: str,
        timeout_ms: int = 15000,
    ):
        self.screenshot_dir = Path(screenshot_dir)
        self.gateway_url = gateway_url.rstrip("/")
        self.timeout_ms = timeout_ms
        self._playwright = None
        self._browser = None

        parsed = urlparse(self.gateway_url)
        self._allowed_origin = f"{parsed.scheme}://{parsed.netloc}"

    async def startup(self) -> None:
        self.screenshot_dir.mkdir(parents=True, exist_ok=True)

        try:
            from playwright.async_api import async_playwright

            self._playwright = await async_playwright().start()
            self._browser = await self._playwright.chromium.launch(
                headless=True,
                args=[
                    "--no-sandbox",
                    "--disable-setuid-sandbox",
                    "--disable-gpu",
                    "--disable-dev-shm-usage",
                ],
            )
            logger.info(
                "Screenshot service started",
                extra={"screenshot_dir": str(self.screenshot_dir)},
            )
        except Exception:
            logger.exception(
                "Failed to start screenshot service — screenshots will be disabled"
            )
            self._browser = None

    async def shutdown(self) -> None:
        if self._browser:
            try:
                await self._browser.close()
            except Exception:
                logger.warning("Error closing browser")
        if self._playwright:
            try:
                await self._playwright.stop()
            except Exception:
                logger.warning("Error stopping playwright")
        self._browser = None
        self._playwright = None

    @property
    def available(self) -> bool:
        return self._browser is not None

    def get_path(self, content_hash: str) -> Path | None:
        path = self.screenshot_dir / f"{content_hash}.jpg"
        return path if path.is_file() else None

    def delete(self, content_hash: str) -> bool:
        path = self.screenshot_dir / f"{content_hash}.jpg"
        try:
            path.unlink(missing_ok=True)
            return True
        except OSError:
            logger.warning(
                "Failed to delete screenshot",
                extra={"content_hash": content_hash},
            )
            return False

    async def capture(self, tx_id: str, content_hash: str) -> bool:
        if not self.available:
            return False

        dest = self.screenshot_dir / f"{content_hash}.jpg"
        if dest.is_file():
            return True

        url = f"{self.gateway_url}/{tx_id}"
        allowed_origin = self._allowed_origin
        context = None

        try:
            context = await self._browser.new_context(
                viewport={"width": 1280, "height": 720},
                java_script_enabled=True,
            )
            page = await context.new_page()

            # Block all requests outside the gateway origin
            async def route_handler(route):
                parsed_req = urlparse(route.request.url)
                parsed_allow = urlparse(allowed_origin)
                if (
                    parsed_req.scheme == parsed_allow.scheme
                    and parsed_req.hostname == parsed_allow.hostname
                    and (parsed_req.port or None) == (parsed_allow.port or None)
                ):
                    await route.continue_()
                else:
                    await route.abort()

            await page.route("**/*", route_handler)

            # Auto-accept dialogs (phishing pages use alert/confirm traps)
            async def handle_dialog(dialog):
                await dialog.accept()

            page.on("dialog", handle_dialog)

            try:
                await page.goto(
                    url,
                    wait_until="networkidle",
                    timeout=self.timeout_ms,
                )
            except Exception:
                logger.debug(
                    "Navigation timeout or error, capturing current state",
                    extra={"tx_id": tx_id},
                )

            await page.screenshot(
                path=str(dest),
                type="jpeg",
                quality=80,
            )

            logger.info(
                "screenshot_captured",
                extra={
                    "tx_id": tx_id,
                    "content_hash": content_hash,
                    "size_bytes": dest.stat().st_size,
                },
            )
            return True

        except Exception:
            logger.exception(
                "screenshot_failed",
                extra={"tx_id": tx_id, "content_hash": content_hash},
            )
            # Clean up partial file
            dest.unlink(missing_ok=True)
            return False
        finally:
            if context:
                try:
                    await context.close()
                except Exception:
                    pass
