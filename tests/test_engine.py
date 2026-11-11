# -----------------------------------------------------------------------------
# AI-Security-Audit-Skills
# Author   : Vijaya Kumar L  (Rise With VJ)
# GitHub   : https://github.com/risewithvj
# LinkedIn : https://www.linkedin.com/in/vijayakumarl/
# License  : MIT
# -----------------------------------------------------------------------------
"""Engine tests. Standard library only: python -m unittest discover -s tests"""

from __future__ import annotations

import json
import os
import shutil
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
SCRIPTS = ROOT / "skills" / "ai-security-audit" / "scripts"
FIXTURE = ROOT / "tests" / "fixtures" / "vuln-hr-portal"
FINDINGS = ROOT / "tests" / "fixtures" / "vuln-hr-portal.findings.json"
sys.path.insert(0, str(SCRIPTS))

from aisa_lib import common, normalize, pii, scanners, stack  # noqa: E402
from aisa_lib.validate import check_cvss_vector, validate_findings, validate_ledger  # noqa: E402

SCHEMA = ROOT / "skills" / "ai-security-audit" / "schema" / "findings.schema.json"


def aisa(*args, env=None):
    return subprocess.run([sys.executable, str(SCRIPTS / "aisa.py"), *args], capture_output=True, text=True, env=env, timeout=600)


class EngineTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.tmp = Path(tempfile.mkdtemp(prefix="aisa-test-"))
        # Semgrep skips folders named tests/, so audit a copy outside the repo tree.
        cls.target = cls.tmp / "vuln-hr-portal"
        shutil.copytree(FIXTURE, cls.target)
        cls.env = dict(os.environ, AISA_REPORTS_DIR=str(cls.tmp / "reports"))
        r = aisa("init", "--target", str(cls.target), "--client", "Test Org", "--app", "Vuln HR Portal", env=cls.env)
        assert r.returncode == 0, r.stderr + r.stdout
        cls.rundir = cls.tmp / "reports" / "vuln-hr-portal" / "run-1"

    @classmethod
    def tearDownClass(cls):
        shutil.rmtree(cls.tmp, ignore_errors=True)

    def setUp(self):
        shutil.copy(FINDINGS, self.rundir / "findings.json")

    def test_stack_detection(self):
        st = stack.detect(self.target)
        for tag in ("express", "supabase", "payments", "jwt", "india_pii"):
            self.assertIn(tag, st["features"])
        self.assertIn("checklists/api-authorization.md", st["suggested_checklists"])
        self.assertIn("checklists/payments.md", st["suggested_checklists"])

    def test_valid_findings_pass(self):
        r = validate_findings(self.rundir, SCHEMA)
        self.assertTrue(r["ok"], r["errors"])
        self.assertEqual(r["counts"]["confirmed"], 5)

    def _tamper(self, fn):
        d = json.loads((self.rundir / "findings.json").read_text())
        fn(d["findings"])
        (self.rundir / "findings.json").write_text(json.dumps(d))
        return validate_findings(self.rundir, SCHEMA)

    def test_fabricated_snippet_fails(self):
        r = self._tamper(lambda f: f[0]["trace"][2].update(snippet="db.query(req.params.employeeId)"))
        self.assertFalse(r["ok"])
        self.assertTrue(any("snippet not found" in e for e in r["errors"]))

    def test_missing_file_fails(self):
        r = self._tamper(lambda f: f[0]["trace"][0].update(file="src/does-not-exist.js"))
        self.assertTrue(any("does not exist" in e for e in r["errors"]))

    def test_path_escape_fails(self):
        r = self._tamper(lambda f: f[0]["trace"][0].update(file="../../etc/passwd"))
        self.assertTrue(any("relative to the target" in e for e in r["errors"]))

    def test_severity_on_needs_validation_fails(self):
        r = self._tamper(lambda f: f[5].update(severity="High"))
        self.assertTrue(any("only confirmed" in e for e in r["errors"]))

    def test_uplift_needs_rationale(self):
        r = self._tamper(lambda f: f[0].pop("severity_rationale"))
        self.assertTrue(any("severity_rationale" in e for e in r["errors"]))

    def test_two_band_uplift_fails(self):
        r = self._tamper(lambda f: f[4].update(severity="Critical"))
        self.assertTrue(any("at most one band" in e for e in r["errors"]))

    def test_hedge_word_fails(self):
        r = self._tamper(lambda f: f[2].update(title="SQL injection might expose data"))
        self.assertTrue(any("hedge word" in e for e in r["errors"]))

    def test_unredacted_secret_fails(self):
        r = self._tamper(lambda f: f[1].update(description=f[1]["description"] + " key AKIAABCDEFGHIJKLMNOP"))
        self.assertTrue(any("unredacted" in e for e in r["errors"]))

    def test_cvss_vector_syntax(self):
        self.assertEqual(check_cvss_vector("CVSS:4.0/AV:N/AC:L/AT:N/PR:L/UI:N/VC:H/VI:N/VA:N/SC:N/SI:N/SA:N"), [])
        self.assertTrue(check_cvss_vector("CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:N/A:N"))
        self.assertTrue(check_cvss_vector("CVSS:4.0/AV:X/AC:L/AT:N/PR:L/UI:N/VC:H/VI:N/VA:N/SC:N/SI:N/SA:N"))

    def test_ledger_rules(self):
        (self.rundir / "coverage-ledger.json").write_text(json.dumps([
            {"coverage_id": "a", "surface": "s", "boundary": "b", "attack_class": "c", "status": "covered", "reviewed_paths": []}]))
        self.assertFalse(validate_ledger(self.rundir)["ok"])
        (self.rundir / "coverage-ledger.json").write_text(json.dumps([
            {"coverage_id": "a", "surface": "s", "boundary": "b", "attack_class": "c", "status": "covered", "reviewed_paths": ["x.js"]}]))
        self.assertTrue(validate_ledger(self.rundir)["ok"])

    def test_secret_lead_dedup_across_scanners(self):
        # A dotfile secret reported by Gitleaks as ".env.local" and by Trivy as
        # "./.env.local" must normalise to the same path and merge into one lead.
        work = Path(tempfile.mkdtemp(prefix="aisa-norm-"))
        try:
            (work / ".env.local").write_text("SECRET=x\n", encoding="utf-8")
            raw = work / "raw"
            raw.mkdir()
            (raw / "gitleaks.json").write_text(json.dumps([
                {"File": ".env.local", "RuleID": "private-key", "StartLine": 2, "Description": "Private Key"}
            ]), encoding="utf-8")
            (raw / "trivy.json").write_text(json.dumps({
                "Results": [{"Target": "./.env.local", "Class": "secret",
                             "Secrets": [{"RuleID": "private-key", "StartLine": 2, "Severity": "HIGH", "Title": "Asymmetric Private Key"}]}]
            }), encoding="utf-8")
            out = normalize.normalize(work, raw)
            secrets = [x for x in out["leads"] if x["kind"] == "secret"]
            self.assertEqual(len(secrets), 1, secrets)
            self.assertEqual(secrets[0]["file"], ".env.local")
            self.assertEqual(sorted(secrets[0]["tools"]), ["gitleaks", "trivy"])
        finally:
            shutil.rmtree(work, ignore_errors=True)

    def test_norm_path_keeps_leading_dot(self):
        self.assertEqual(normalize._norm_path(self.target, "./.env.local"), ".env.local")
        self.assertEqual(normalize._norm_path(self.target, ".env.local"), ".env.local")
        self.assertEqual(normalize._norm_path(self.target, "src\\lib\\auth.js"), "src/lib/auth.js")

    def test_which_searches_extra_bin_dirs(self):
        # A tool installed into a package-manager dir that is not on PATH (pip
        # --user Scripts, winget, scoop, ~/.local/bin) must still be found.
        d = Path(tempfile.mkdtemp(prefix="aisa-bin-"))
        try:
            exe = d / ("tool.exe" if common.IS_WINDOWS else "tool")
            exe.write_text("", encoding="utf-8")
            if not common.IS_WINDOWS:
                os.chmod(exe, 0o755)
            self.assertIsNone(common.which("tool"))  # not on PATH
            orig = common._extra_bin_dirs
            common._extra_bin_dirs = lambda: [d]
            try:
                self.assertIsNotNone(common.which("tool"))
            finally:
                common._extra_bin_dirs = orig
        finally:
            shutil.rmtree(d, ignore_errors=True)

    def test_walk_skips_heavy_and_db_volume_dirs(self):
        work = Path(tempfile.mkdtemp(prefix="aisa-walk-"))
        try:
            (work / "src").mkdir()
            (work / "src" / "app.php").write_text("<?php echo 1;", encoding="utf-8")
            for heavy in ("wp-admin", "wp-includes", "wpvividbackups"):
                (work / heavy).mkdir()
                (work / heavy / "x.php").write_text("<?php", encoding="utf-8")
            (work / "db").mkdir()
            (work / "db" / "ibdata1").write_text("binary", encoding="utf-8")
            (work / "docker-compose.yml").write_text(
                "services:\n  db:\n    volumes:\n      - ./db:/var/lib/mysql\n", encoding="utf-8")
            self.assertEqual(common.compose_db_dirs(work), {(work / "db").resolve()})
            got = {common.rel(work, p) for p in common.walk_files(work, None, common.compose_db_dirs(work))}
            self.assertIn("src/app.php", got)
            self.assertFalse(any(x.startswith(("wp-admin/", "wp-includes/", "wpvividbackups/", "db/")) for x in got), got)
        finally:
            shutil.rmtree(work, ignore_errors=True)

    def test_project_root_target_with_scope(self):
        # init on a project root (with a DB bind-mount) + --scope must not walk the DB
        # volume, and docker-compose.yml at the root must be citable in findings.json.
        work = Path(tempfile.mkdtemp(prefix="aisa-root-"))
        reports = Path(tempfile.mkdtemp(prefix="aisa-root-rep-"))
        env = dict(os.environ, AISA_REPORTS_DIR=str(reports))
        try:
            (work / "src").mkdir()
            (work / "src" / "app.php").write_text("<?php echo 1;", encoding="utf-8")
            (work / "db").mkdir()
            (work / "db" / "ibdata1").write_text("x" * 100, encoding="utf-8")
            (work / "docker-compose.yml").write_text(
                "services:\n  db:\n    image: mysql:8\n    volumes:\n      - ./db:/var/lib/mysql\n", encoding="utf-8")
            r = aisa("init", "--target", str(work), "--scope", "src,docker-compose.yml", env=env)
            self.assertEqual(r.returncode, 0, r.stderr + r.stdout)
            rundir = reports / work.name / "run-1"
            st = json.loads((rundir / "stack.json").read_text())
            self.assertNotIn("SQL", [*st["languages"]])  # db/ was not walked
            # a finding can cite docker-compose.yml because the target is the project root
            (rundir / "findings.json").write_text(json.dumps({
                "schema_version": "1.0", "run_id": "t", "framework": "security", "findings": [{
                    "id": "V-01", "verdict": "needs_validation", "title": "compose exposes a port",
                    "class": "config", "description": "d",
                    "trace": [{"file": "docker-compose.yml", "line": 1, "snippet": "services:"}],
                    "missing_fact": "f", "why_verification": "w", "safe_check": "s"}]}))
            res = validate_findings(rundir, SCHEMA)
            self.assertTrue(res["ok"], res["errors"])
        finally:
            shutil.rmtree(work, ignore_errors=True)
            shutil.rmtree(reports, ignore_errors=True)

    def test_erasure_marker_excludes_cache(self):
        self.assertFalse(pii._is_erasure("await redis.del(keys.workspaces(email)); // invalidate cache"))
        self.assertFalse(pii._is_erasure("export const TTL = { leads: 300, users: 900 }"))
        self.assertFalse(pii._is_erasure("await cache.delete(userKey)"))
        self.assertFalse(pii._is_erasure("revalidatePath('/users')"))
        self.assertTrue(pii._is_erasure("await supabaseAdmin.from('users').delete().eq('id', id)"))
        self.assertTrue(pii._is_erasure("function deleteUser(email) {"))
        self.assertTrue(pii._is_erasure("// right to be forgotten endpoint"))

    def test_third_party_recipients(self):
        def hits(s):
            return {k for k, rx in pii.THIRD_RX.items() if rx.search(s)}
        self.assertIn("Supabase (DB/storage/auth)", hits("import { createClient } from '@supabase/supabase-js'"))
        self.assertIn("SMTP / nodemailer", hits("const t = nodemailer.createTransport({ host })"))
        self.assertIn("Google Sheets / Drive API", hits("const sheets = google.sheets({version:'v4'}) // googleapis"))
        self.assertIn("Resend (email)", hits("const r = new Resend(process.env.RESEND_API_KEY)"))

    def test_vendor_path_and_lead_flag(self):
        self.assertTrue(common.is_vendor_path("wp-content/plugins/wpforms/vendor_prefixed/stripe/lib/Charge.php"))
        self.assertTrue(common.is_vendor_path("wp-content/themes/twentytwentyfour/functions.php"))
        self.assertTrue(common.is_vendor_path("wp-content/plugins/elementor/includes/x.php"))
        self.assertTrue(common.is_vendor_path("backend/vendor/guzzle/src/Client.php"))
        self.assertFalse(common.is_vendor_path("wp-content/themes/rebuilto-child/functions.php"))
        self.assertFalse(common.is_vendor_path("src/app/api/leads/route.ts"))
        work = Path(tempfile.mkdtemp(prefix="aisa-vend-"))
        try:
            raw = work / "raw"
            raw.mkdir()
            (raw / "gitleaks.json").write_text(json.dumps([
                {"File": "wp-content/plugins/elementor/x.php", "RuleID": "generic-api-key", "StartLine": 3, "Description": "k"},
                {"File": "src/config.ts", "RuleID": "generic-api-key", "StartLine": 5, "Description": "k"}]), encoding="utf-8")
            out = normalize.normalize(work, raw)
            byf = {x["file"]: x for x in out["leads"]}
            self.assertTrue(byf["wp-content/plugins/elementor/x.php"]["likely_vendor"])
            self.assertFalse(byf["src/config.ts"]["likely_vendor"])
        finally:
            shutil.rmtree(work, ignore_errors=True)

    def test_india_pii_only_custom_code(self):
        work = Path(tempfile.mkdtemp(prefix="aisa-pii-"))
        try:
            (work / "src").mkdir()
            (work / "src" / "model.js").write_text("const schema = { aadhaar_number: String, pan_card: String };", encoding="utf-8")
            (work / "vendor").mkdir()
            (work / "vendor" / "lib.php").write_text("<?php $salary = 0; $pan_number = '';", encoding="utf-8")
            (work / "node_modules").mkdir()
            (work / "node_modules" / "x.js").write_text("const bank_account_no = 1;", encoding="utf-8")
            st = stack.detect(work)
            self.assertIn("src/model.js", st["india_pii_files"])
            self.assertFalse(any("vendor/" in f or "node_modules/" in f for f in st["india_pii_files"]), st["india_pii_files"])
        finally:
            shutil.rmtree(work, ignore_errors=True)

    def test_stack_skips_vendor_and_public_plugin_contents(self):
        # init --wp speed: stack detection must NOT read the contents of vendored
        # or public-plugin files, so route and PII hints inside Elementor et al.
        # are not consumed - only the project's own custom code is.
        work = Path(tempfile.mkdtemp(prefix="aisa-wp-speed-"))
        try:
            body = "<?php\n// app.get('/records')\n$pan_card = $_GET['a']; $salary = 0;\n"
            pub = work / "wp-content" / "plugins" / "elementor"
            pub.mkdir(parents=True)
            (pub / "app.php").write_text(body, encoding="utf-8")
            custom = work / "wp-content" / "plugins" / "my-custom"
            custom.mkdir(parents=True)
            (custom / "app.php").write_text(body, encoding="utf-8")
            st = stack.detect(work)
            self.assertIn("wp-content/plugins/my-custom/app.php", st["india_pii_files"])
            self.assertIn("wp-content/plugins/my-custom/app.php", st["likely_entry_files"])
            self.assertNotIn("wp-content/plugins/elementor/app.php", st["india_pii_files"])
            self.assertNotIn("wp-content/plugins/elementor/app.php", st["likely_entry_files"])
        finally:
            shutil.rmtree(work, ignore_errors=True)

    def test_wpvulns_components_without_token(self):
        from aisa_lib import wpvulns
        work = Path(tempfile.mkdtemp(prefix="aisa-wp-"))
        try:
            pl = work / "wp-content" / "plugins" / "coolplugin"
            pl.mkdir(parents=True)
            (pl / "readme.txt").write_text("=== Cool Plugin ===\nStable tag: 1.2.3\n", encoding="utf-8")
            th = work / "wp-content" / "themes" / "mytheme"
            th.mkdir(parents=True)
            (th / "style.css").write_text("/*\nTheme Name: My Theme\nVersion: 2.0.1\n*/", encoding="utf-8")
            comps = wpvulns.collect_components(work)
            byslug = {c["slug"]: c for c in comps}
            self.assertEqual(byslug["coolplugin"]["version"], "1.2.3")
            self.assertEqual(byslug["mytheme"]["version"], "2.0.1")
            env = dict(os.environ); env.pop("WPSCAN_API_TOKEN", None)
            os.environ.pop("WPSCAN_API_TOKEN", None)
            run = work / "run"; (run).mkdir()
            out = wpvulns.scan(work, run)
            self.assertFalse(out["checked"])
            self.assertTrue(any("not checked" in d["ids"][0] for d in out["dependencies"]))
        finally:
            shutil.rmtree(work, ignore_errors=True)

    def test_scope_budget_and_offline(self):
        work = Path(tempfile.mkdtemp(prefix="aisa-bud-"))
        try:
            (work / "a.py").write_text("x" * 100, encoding="utf-8")
            b = scanners.scope_budget([str(work)])
            self.assertFalse(b["exceeded"])
            self.assertGreaterEqual(b["files"], 1)
            self.assertGreaterEqual(b["bytes"], 100)
        finally:
            shutil.rmtree(work, ignore_errors=True)
        scanners._ONLINE = None
        os.environ["AISA_FORCE_OFFLINE"] = "1"
        try:
            self.assertFalse(scanners.is_online())
        finally:
            os.environ.pop("AISA_FORCE_OFFLINE", None)
            scanners._ONLINE = None

    def test_semgrep_json_to_sarif_and_normalize(self):
        work = Path(tempfile.mkdtemp(prefix="aisa-sg-"))
        try:
            sg_json = {"results": [{
                "check_id": "rules.sql-injection", "path": "src/db.js",
                "start": {"line": 12}, "end": {"line": 12},
                "extra": {"message": "SQL built from user input", "severity": "ERROR",
                          "metadata": {"cwe": ["CWE-89: SQL Injection"]}}}]}
            sarif = scanners._sarif_from_semgrep_json(sg_json)
            r0 = sarif["runs"][0]["results"][0]
            self.assertEqual(r0["ruleId"], "rules.sql-injection")
            self.assertEqual(r0["level"], "error")
            raw = work / "raw"; raw.mkdir()
            (raw / "semgrep.sarif").write_text(json.dumps(sarif), encoding="utf-8")
            leads = normalize._semgrep(work, raw)
            self.assertEqual(len(leads), 1)
            self.assertEqual(leads[0]["file"], "src/db.js")
            self.assertEqual(leads[0]["line"], 12)
            self.assertIn("CWE-89", leads[0]["cwe"])
            self.assertEqual(leads[0]["severity_hint"], "high")
        finally:
            shutil.rmtree(work, ignore_errors=True)

    def test_sarif_ok_rejects_empty_file(self):
        work = Path(tempfile.mkdtemp(prefix="aisa-sarif-"))
        try:
            (work / "empty.sarif").write_text("", encoding="utf-8")   # 0-byte: the known failure mode
            (work / "full.sarif").write_text("{}", encoding="utf-8")
            self.assertFalse(scanners._sarif_ok(work / "empty.sarif"))
            self.assertFalse(scanners._sarif_ok(work / "missing.sarif"))
            self.assertTrue(scanners._sarif_ok(work / "full.sarif"))
        finally:
            shutil.rmtree(work, ignore_errors=True)

    def test_semgrep_selfcheck_without_semgrep(self):
        orig = scanners._semgrep_exes
        scanners._semgrep_exes = lambda: []
        try:
            chk = scanners.semgrep_selfcheck()
            self.assertFalse(chk["ran"])
            self.assertIn("not found", chk["note"].lower())
        finally:
            scanners._semgrep_exes = orig

    def test_version_of_semgrep_falls_back_to_pysemgrep(self):
        # The semgrep wrapper can print a pysemgrep exec error instead of a
        # version; version_of must then report the pysemgrep version.
        orig_vl, orig_which = scanners._version_line, scanners.which
        scanners.which = lambda name: {"semgrep": "/x/semgrep", "pysemgrep": "/x/pysemgrep"}.get(name)
        scanners._version_line = lambda exe, args: (
            'executing pysemgrep failed: run ["pysemgrep"] : No such file or directory'
            if exe.endswith("semgrep") and not exe.endswith("pysemgrep") else "1.95.0")
        try:
            v = scanners.version_of("semgrep")
            self.assertIn("pysemgrep", v)
            self.assertIn("1.95.0", v)
        finally:
            scanners._version_line, scanners.which = orig_vl, orig_which

    def test_exposed_file_detector(self):
        from aisa_lib import exposed
        work = Path(tempfile.mkdtemp(prefix="aisa-exp-"))
        try:
            wp = work / "wordpress"
            (wp / "wp-content" / "uploads").mkdir(parents=True)
            (wp / "wp-content" / "wpvividbackups").mkdir(parents=True)
            (wp / "backup.zip").write_text("x" * 50, encoding="utf-8")
            (wp / "debug.log").write_text("err", encoding="utf-8")
            (wp / ".env.local").write_text("SECRET=1", encoding="utf-8")
            (wp / "wp-content" / "functions.php-19-11-2025").write_text("<?php", encoding="utf-8")
            (wp / "db.sql").write_text("CREATE TABLE", encoding="utf-8")
            # New backup-archive extensions (All-in-One WP Migration .wpress, .tgz).
            (wp / "wp-content" / "uploads" / "site.wpress").write_text("x", encoding="utf-8")
            (wp / "wp-content" / "uploads" / "snapshot.tgz").write_text("x", encoding="utf-8")
            # A file with no archive extension but inside a known backup OUTPUT dir.
            (wp / "wp-content" / "wpvividbackups" / "part1.incremental").write_text("x", encoding="utf-8")
            # A large (>1 MB) web-root archive must be flagged large, with its size.
            (wp / "new_website_backup.zip").write_bytes(b"x" * (1024 * 1024 + 10))
            (work / "src").mkdir()
            (work / "src" / "app.js").write_text("ok", encoding="utf-8")
            (work / "vendor").mkdir()
            (work / "vendor" / "lib.bak").write_text("x", encoding="utf-8")  # vendored leftover -> skipped
            # The WPvivid backup PLUGIN's own source folder must NOT be flagged
            # just because its name contains "backup" (it is not a backup output).
            pl = wp / "wp-content" / "plugins" / "wpvivid-backuprestore" / "includes"
            pl.mkdir(parents=True)
            (pl / "class-backup.php").write_text("<?php", encoding="utf-8")
            # Walk the WHOLE document root even when a code --scope is given.
            hits = exposed.find_exposed(work, scope=["wordpress/wp-content/themes"])
            byfile = {h["file"]: h for h in hits}
            files = set(byfile)
            for f in ("wordpress/backup.zip", "wordpress/debug.log", "wordpress/.env.local",
                      "wordpress/wp-content/functions.php-19-11-2025", "wordpress/db.sql",
                      "wordpress/wp-content/uploads/site.wpress", "wordpress/wp-content/uploads/snapshot.tgz",
                      "wordpress/wp-content/wpvividbackups/part1.incremental"):
                self.assertIn(f, files)
            self.assertNotIn("src/app.js", files)
            self.assertNotIn("vendor/lib.bak", files)
            self.assertNotIn("wordpress/wp-content/plugins/wpvivid-backuprestore/includes/class-backup.php", files)
            self.assertTrue(byfile["wordpress/new_website_backup.zip"]["large"])
            self.assertFalse(byfile["wordpress/backup.zip"]["large"])
            self.assertTrue(all(isinstance(h["bytes"], int) for h in hits))
            raw = work / "raw"
            raw.mkdir()
            (raw / "exposed.json").write_text(json.dumps(hits), encoding="utf-8")
            out = normalize.normalize(work, raw)
            exp = [x for x in out["leads"] if x["kind"] == "exposed_file"]
            self.assertGreaterEqual(len(exp), 8)
            self.assertEqual(out["counts"]["exposed_files"], len(exp))
        finally:
            shutil.rmtree(work, ignore_errors=True)

    def test_benchmark_scorecard(self):
        from aisa_lib import benchmark
        labels = ROOT / "tests" / "fixtures" / "vuln-hr-portal.labels.json"
        res = benchmark.run(self.rundir, str(labels))
        c = res["counts"]
        self.assertEqual(c["matched"], 5)   # the 5 confirmed planted issues
        self.assertEqual(c["missed"], 1)    # jwt-fallback is only needs_validation
        self.assertEqual(c["extra"], 0)
        self.assertEqual({m.get("id") for m in res["missed"]}, {"jwt-fallback-secret"})
        self.assertIn("false_positive_rate", c)
        self.assertEqual(c["reconciled_extra"], 0)

    def test_benchmark_exact_id_acronym_and_reconcile(self):
        from aisa_lib import benchmark
        work = Path(tempfile.mkdtemp(prefix="aisa-bm-"))
        confirmed = [
            {"id": "F1", "verdict": "confirmed", "class": "Stored XSS",
             "title": "persisted", "trace": [{"file": "routes/user.js"}]},
            {"id": "F2", "verdict": "confirmed", "class": "Noise",
             "title": "dup of xss", "trace": [{"file": "routes/user.js"}]},
            {"id": "F3", "verdict": "confirmed", "class": "Other",
             "title": "real fp", "trace": [{"file": "z.js"}]},
        ]
        labels = [
            {"id": "usernameXss", "class": "XSS", "file": "routes/user.js"},  # acronym match
            {"id": "mapped", "finding_id": "F3", "class": "whatever", "file": "zzz.js"},  # exact id
        ]
        (work / "findings.json").write_text(json.dumps({"findings": confirmed}), encoding="utf-8")
        lf = work / "labels.json"
        lf.write_text(json.dumps({"labels": labels}), encoding="utf-8")
        res = benchmark.run(work, str(lf))
        got = {m["label"]["id"]: m["finding"] for m in res["matched"]}
        self.assertEqual(got.get("usernameXss"), "F1")   # XSS acronym on shared file
        self.assertEqual(got.get("mapped"), "F3")        # exact finding_id mapping
        # F2 is an extra that reconciles to the XSS label (same file+class), not an FP.
        self.assertEqual(res["counts"]["extra"], 0)
        self.assertEqual(res["counts"]["reconciled_extra"], 1)
        self.assertEqual(res["counts"]["false_positive_rate"], 0.0)

    def test_exclude_globs(self):
        from aisa_lib import common
        common.set_global_exclude(["data/static/codefixes/**", "**/private/**", "seed"])
        try:
            self.assertTrue(common.is_excluded("data/static/codefixes/a.ts"))
            self.assertTrue(common.is_excluded("frontend/src/private/key.pem"))
            self.assertTrue(common.is_excluded("seed/users.json"))
            self.assertFalse(common.is_excluded("src/app.js"))
        finally:
            common.set_global_exclude([])

    def test_wp_profile_init(self):
        work = Path(tempfile.mkdtemp(prefix="aisa-wp-prof-"))
        reports = Path(tempfile.mkdtemp(prefix="aisa-wp-rep-"))
        env = dict(os.environ, AISA_REPORTS_DIR=str(reports))
        try:
            (work / "wp-content" / "themes" / "custom-theme").mkdir(parents=True)
            (work / "wp-content" / "themes" / "custom-theme" / "style.css").write_text("/* Version: 1.0 */", encoding="utf-8")
            (work / "wp-content" / "plugins" / "elementor").mkdir(parents=True)
            (work / "wp-content" / "plugins" / "elementor" / "readme.txt").write_text("Stable tag: 3.1", encoding="utf-8")
            (work / "wp-content" / "plugins" / "my-custom").mkdir(parents=True)
            (work / "wp-content" / "mu-plugins").mkdir(parents=True)
            (work / "wp-config.php").write_text("<?php // config", encoding="utf-8")
            (work / "docker-compose.yml").write_text("services: {}\n", encoding="utf-8")
            r = aisa("init", "--target", str(work), "--wp", env=env)
            self.assertEqual(r.returncode, 0, r.stderr + r.stdout)
            rundir = reports / work.name / "run-1"
            meta = json.loads((rundir / "run-metadata.json").read_text())
            self.assertEqual(set(meta["scope"]), {
                "wp-content/themes", "wp-content/plugins", "wp-content/mu-plugins",
                "wp-config.php", "docker-compose.yml"})
            self.assertEqual(meta["wp_public_plugins"], ["elementor"])
            self.assertTrue((rundir / "wpvulns.json").exists())
            st = json.loads((rundir / "stack.json").read_text())
            self.assertIn("checklists/wordpress.md", st["suggested_checklists"])
        finally:
            shutil.rmtree(work, ignore_errors=True)
            shutil.rmtree(reports, ignore_errors=True)

    def test_severity_doc_trivial_integrity_vi_none(self):
        # Guidance must state that a trivial integrity write nothing
        # security-relevant consumes scores VI:N, not VI:L.
        doc = (ROOT / "skills" / "ai-security-audit" / "rules" / "severity-and-scoring.md").read_text(encoding="utf-8")
        self.assertIn("VI:N", doc)
        low = doc.lower()
        self.assertIn("no security-relevant logic ever reads back", low)
        self.assertTrue("counter" in low and "cosmetic" in low)

    def test_redaction(self):
        s = "token ghp_" + "a" * 36
        self.assertNotIn("a" * 36, common.redact_text(s))
        self.assertTrue(common.find_secrets(s))

    def test_verhoeff(self):
        # Build a valid check digit for an arbitrary 11-digit body; never a real number.
        body = "23412341234"
        valid = next(body + str(d) for d in range(10) if pii.verhoeff_ok(body + str(d)))
        self.assertTrue(pii.verhoeff_ok(valid))
        self.assertFalse(pii.verhoeff_ok(valid[:-1] + str((int(valid[-1]) + 1) % 10)))

    def test_pii_inventory(self):
        inv = pii.inventory(self.target)
        for k in ("PAN", "Aadhaar number", "Bank account / IFSC / UPI"):
            self.assertIn(k, inv["data_types"])
        self.assertTrue(any("payslips.js" in x["file"] for x in inv["possible_pii_in_logs"]))
        self.assertIn("Payment gateways", inv["third_party_recipients"])

    def test_report_builds(self):
        try:
            import docx  # noqa: F401
        except ImportError:
            self.skipTest("python-docx not installed")
        r = aisa("report", "--run", str(self.rundir), "--no-pdf", env=self.env)
        self.assertEqual(r.returncode, 0, r.stdout + r.stderr)
        out = self.rundir / "AI-Security-Audit-Report.docx"
        self.assertTrue(out.exists())
        from docx import Document
        text = "\n".join(p.text for p in Document(str(out)).paragraphs)
        self.assertIn("SOURCE CODE SECURITY AUDIT REPORT", text)
        self.assertIn("F-01", text)

    def test_to_pdf_graceful_without_converter(self):
        try:
            import docx  # noqa: F401
        except ImportError:
            self.skipTest("python-docx not installed")
        from aisa_lib import report_docx
        # Only meaningful where no PDF converter exists (e.g. Linux CI with no
        # LibreOffice, no Word, no docx2pdf): to_pdf must return None, not raise.
        if report_docx._libreoffice_exe() or common.IS_WINDOWS:
            self.skipTest("a PDF converter is available on this host")
        from docx import Document
        doc = Document()
        doc.add_paragraph("x")
        p = self.rundir / "tmp-pdf-test.docx"
        doc.save(str(p))
        self.assertIsNone(report_docx.to_pdf(p))

    def test_osv_skipped_reports_lockfile_hint(self):
        try:
            import docx  # noqa: F401
        except ImportError:
            self.skipTest("python-docx not installed")
        meta_path = self.rundir / "run-metadata.json"
        leads_path = self.rundir / "leads.json"
        meta_backup = meta_path.read_text()
        try:
            meta = json.loads(meta_backup)
            meta["scanners"] = {
                "trivy": {"status": "ok", "version": "0.0", "purpose": "deps"},
                "osv-scanner": {"status": "skipped", "note": "no lockfile found", "version": "0.0", "purpose": "lockfile vulns"},
            }
            meta_path.write_text(json.dumps(meta))
            leads_path.write_text(json.dumps({"leads": [], "dependencies": [], "counts": {}}))
            r = aisa("report", "--run", str(self.rundir), "--no-pdf", env=self.env)
            self.assertEqual(r.returncode, 0, r.stdout + r.stderr)
            from docx import Document
            d = Document(str(self.rundir / "AI-Security-Audit-Report.docx"))
            para = "\n".join(p.text for p in d.paragraphs)
            tables = "\n".join(c.text for t in d.tables for row in t.rows for c in row.cells)
            self.assertIn("commit a lockfile", para.lower())
            self.assertIn("Skipped (no lockfile)", tables)
        finally:
            meta_path.write_text(meta_backup)
            if leads_path.exists():
                leads_path.unlink()

    def test_dpdp_findings_and_report(self):
        try:
            import docx  # noqa: F401
        except ImportError:
            self.skipTest("python-docx not installed")
        shutil.copy(ROOT / "tests" / "fixtures" / "vuln-hr-portal.dpdp.findings.json", self.rundir / "findings.json")
        r = validate_findings(self.rundir, SCHEMA)
        self.assertTrue(r["ok"], r["errors"])
        r = aisa("report", "--run", str(self.rundir), "--no-pdf", env=self.env)
        self.assertEqual(r.returncode, 0, r.stdout + r.stderr)
        from docx import Document
        text = "\n".join(p.text for p in Document(str(self.rundir / "DPDP-Compliance-Audit-Report.docx")).paragraphs)
        self.assertIn("DPDP ACT 2023 COMPLIANCE AUDIT REPORT", text)
        self.assertIn("not legal advice", text)

    def test_dpdp_needs_obligation(self):
        shutil.copy(ROOT / "tests" / "fixtures" / "vuln-hr-portal.dpdp.findings.json", self.rundir / "findings.json")
        r = self._tamper(lambda f: f[0]["dpdp"].pop("obligation"))
        self.assertFalse(r["ok"])

    def test_report_refuses_invalid_records(self):
        self._tamper(lambda f: f[0]["trace"][2].update(snippet="not in the file"))
        r = aisa("report", "--run", str(self.rundir), "--no-pdf", env=self.env)
        self.assertNotEqual(r.returncode, 0)


if __name__ == "__main__":
    unittest.main()
