from pathlib import Path
import os
import shutil
import re
import subprocess
import tempfile
import unittest


ROOT = Path(__file__).resolve().parents[1]
CHROME = (shutil.which("chromium") or shutil.which("google-chrome")
          or shutil.which("chromium-browser"))
if not CHROME:
    mac_chrome = Path("/Applications/Google Chrome.app/Contents/MacOS/Google Chrome")
    CHROME = str(mac_chrome) if mac_chrome.is_file() else None


@unittest.skipUnless(CHROME, "Chrome or Chromium is required for board browser tests")
class BoardTests(unittest.TestCase):
    def run_browser(self, checks, setup=""):
        html = (ROOT / "QUANTUMTRACE_TASK_BOARD.html").read_text()
        html = html.replace("<script>\n'use strict';", f"<script>{setup}</script><script>\n'use strict';", 1)
        script = """
        <script>
        (async () => {
          const assert = (condition, message) => { if (!condition) throw new Error(message); };
          try {
        """ + checks + """
            document.body.textContent = 'BOARD_TEST_PASSED';
          } catch (error) {
            document.body.textContent = 'BOARD_TEST_FAILED: ' + error.message;
          }
        })();
        </script>
        """
        with tempfile.TemporaryDirectory() as temp:
            page = Path(temp) / "board.html"
            page.write_text(html.replace("</body>", script + "</body>"))
            # CI's restricted Chrome sandbox cannot start; only trusted local board fixtures are loaded.
            sandbox_flags = ["--no-sandbox"] if os.environ.get("GITHUB_ACTIONS") == "true" else []
            result = subprocess.run(
                [CHROME, *sandbox_flags, "--headless", "--no-first-run", "--no-default-browser-check",
                 f"--user-data-dir={temp}/profile", "--virtual-time-budget=2000",
                 "--dump-dom", page.as_uri()],
                capture_output=True, text=True, timeout=30,
            )
        self.assertEqual(result.returncode, 0, result.stderr[:2000])
        body = re.search(r"<body>(.*?)</body>", result.stdout, re.DOTALL)
        self.assertIsNotNone(body, "Browser returned no document body")
        self.assertEqual(body.group(1).strip(), "BOARD_TEST_PASSED")

    def test_filters_progress_import_and_keyboard_focus(self):
        self.run_browser("""
          assert(document.querySelectorAll('[data-task]').length === 25, 'Initial task count');
          const owner = $('owner-network');
          owner.value = '<img src=x onerror=alert(1)>';
          owner.dispatchEvent(new Event('input', {bubbles:true}));
          $('search').value = 'network';
          $('search').dispatchEvent(new Event('input'));
          assert(!$('board').querySelector('img'), 'Owner HTML was not escaped');
          assert($('owner-network').value === owner.value, 'Owner value lost');
          $('search').value = '';
          $('search').dispatchEvent(new Event('input'));
          $('role-filter').value = 'network';
          $('role-filter').dispatchEvent(new Event('change'));
          $('status-filter').value = 'open';
          $('status-filter').dispatchEvent(new Event('change'));
          assert(document.querySelectorAll('[data-task]').length === 5, 'Role filter');
          for (let i = 1; i <= 5; i++) {
            const checkbox = $('check-n' + i);
            checkbox.focus(); checkbox.click();
            assert(document.activeElement !== document.body, 'Focus lost on completion');
          }
          assert(document.activeElement === $('status-filter'), 'Empty view focus');
          assert($('task-total').textContent === '5 / 25', 'Progress totals');
          assert(JSON.parse(localStorage.getItem(STORAGE_KEY)).done.n5, 'Progress not saved');
          $('clear-filters').click();
          assert(document.querySelectorAll('[data-task]').length === 25, 'Clear filters');
          $('tab-board').dispatchEvent(new KeyboardEvent('keydown', {key:'ArrowRight', bubbles:true}));
          assert(!$('panel-plan').hidden && $('panel-board').hidden, 'Keyboard tab switch');
          const importSnapshot = async (payload) => {
            const transfer = new DataTransfer();
            transfer.items.add(new File([JSON.stringify(payload)], 'progress.json', {type:'application/json'}));
            File.prototype.text = async () => JSON.stringify(payload);
            $('import-file').files = transfer.files;
            $('import-file').dispatchEvent(new Event('change'));
            await Promise.resolve();
          };
          window.confirm = () => true;
          await importSnapshot({format:'quantumtrace-team-board',version:1,owners:{cloud:'Santiago'},done:{c1:true}});
          assert(state.owners.cloud === 'Santiago' && state.done.c1 && !state.done.n1, 'Import replacement');
          await importSnapshot({format:'quantumtrace-team-board',version:1,owners:{},done:{c1:'yes'}});
          assert(state.done.c1 && $('flash').textContent.startsWith('Import failed:'), 'Invalid import changed state');
          window.confirm = () => false;
          await importSnapshot({format:'quantumtrace-team-board',version:1,owners:{},done:{}});
          assert(state.done.c1, 'Cancelled import changed state');
        """)

    def test_storage_unavailable_keeps_board_usable(self):
        self.run_browser("""
          assert($('storage-note').textContent.includes('unavailable'), 'Missing storage warning');
          $('check-n1').click();
          assert($('task-total').textContent === '1 / 25', 'In-memory progress failed');
          assert(state.done.n1, 'State not retained');
          assert($('storage-note').textContent.includes('only in this tab'), 'Missing save failure warning');
        """, setup="""
          Storage.prototype.getItem = Storage.prototype.setItem = () => {throw new Error('Storage denied');};
        """)
