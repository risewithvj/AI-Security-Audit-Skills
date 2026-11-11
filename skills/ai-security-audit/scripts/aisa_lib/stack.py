# -----------------------------------------------------------------------------
# AI-Security-Audit-Skills
# Author   : Vijaya Kumar L  (Rise With VJ)
# GitHub   : https://github.com/risewithvj
# LinkedIn : https://www.linkedin.com/in/vijayakumarl/
# License  : MIT
# -----------------------------------------------------------------------------
"""Detect the target's stack so only relevant checklists and rules load."""

from __future__ import annotations

import json
import re
from collections import Counter
from pathlib import Path

from .common import compose_db_dirs, is_vendor_path, read_text, rel, walk_files

EXT_LANG = {
    ".js": "JavaScript", ".mjs": "JavaScript", ".cjs": "JavaScript", ".jsx": "JavaScript",
    ".ts": "TypeScript", ".tsx": "TypeScript", ".py": "Python", ".rb": "Ruby", ".php": "PHP",
    ".java": "Java", ".kt": "Kotlin", ".kts": "Kotlin", ".scala": "Scala", ".go": "Go",
    ".rs": "Rust", ".cs": "C#", ".vb": "VB.NET", ".swift": "Swift", ".m": "Objective-C",
    ".dart": "Dart", ".c": "C", ".h": "C", ".cc": "C++", ".cpp": "C++", ".hpp": "C++",
    ".ex": "Elixir", ".exs": "Elixir", ".sol": "Solidity", ".vue": "Vue", ".svelte": "Svelte",
    ".astro": "Astro", ".gs": "Apps Script", ".sql": "SQL", ".tf": "Terraform", ".lua": "Lua",
}

# dependency name (lowercase) -> (feature tag, label)
NODE_DEPS = {
    "next": ("nextjs", "Next.js"), "react": ("react", "React"), "vue": ("vue", "Vue"),
    "nuxt": ("nuxt", "Nuxt"), "@angular/core": ("angular", "Angular"), "svelte": ("svelte", "Svelte"),
    "@sveltejs/kit": ("sveltekit", "SvelteKit"), "astro": ("astro", "Astro"), "vite": ("vite", "Vite"),
    "express": ("express", "Express"), "@nestjs/core": ("nestjs", "NestJS"), "fastify": ("fastify", "Fastify"),
    "koa": ("koa", "Koa"), "hono": ("hono", "Hono"), "@remix-run/node": ("remix", "Remix"),
    "@supabase/supabase-js": ("supabase", "Supabase"), "firebase": ("firebase", "Firebase"),
    "firebase-admin": ("firebase", "Firebase Admin"), "convex": ("convex", "Convex"),
    "@prisma/client": ("prisma", "Prisma"), "mongoose": ("mongodb", "Mongoose"), "sequelize": ("sql", "Sequelize"),
    "typeorm": ("sql", "TypeORM"), "drizzle-orm": ("sql", "Drizzle"), "knex": ("sql", "Knex"),
    "pg": ("sql", "node-postgres"), "mysql2": ("sql", "mysql2"),
    "stripe": ("payments", "Stripe"), "razorpay": ("payments", "Razorpay"), "@paypal/checkout-server-sdk": ("payments", "PayPal"),
    "openai": ("llm", "OpenAI SDK"), "@anthropic-ai/sdk": ("llm", "Anthropic SDK"), "@google/generative-ai": ("llm", "Gemini SDK"),
    "@google/genai": ("llm", "Gemini SDK"), "langchain": ("llm", "LangChain"), "@langchain/core": ("llm", "LangChain"),
    "ai": ("llm", "Vercel AI SDK"), "llamaindex": ("llm", "LlamaIndex"), "@modelcontextprotocol/sdk": ("mcp", "MCP SDK"),
    "graphql": ("graphql", "GraphQL"), "@apollo/server": ("graphql", "Apollo Server"), "socket.io": ("websocket", "Socket.IO"),
    "ws": ("websocket", "ws"), "jsonwebtoken": ("jwt", "jsonwebtoken"), "jose": ("jwt", "jose"),
    "next-auth": ("auth", "NextAuth"), "@auth/core": ("auth", "Auth.js"), "passport": ("auth", "Passport"),
    "@clerk/nextjs": ("auth", "Clerk"), "multer": ("uploads", "Multer"), "formidable": ("uploads", "Formidable"),
    "react-native": ("mobile", "React Native"), "expo": ("mobile", "Expo"), "electron": ("desktop", "Electron"),
    "@tauri-apps/api": ("desktop", "Tauri"), "axios": ("http_client", "axios"), "node-fetch": ("http_client", "node-fetch"),
    "puppeteer": ("headless_browser", "Puppeteer"), "playwright": ("headless_browser", "Playwright"),
    "bullmq": ("queue", "BullMQ"), "amqplib": ("queue", "RabbitMQ"), "kafkajs": ("queue", "Kafka"),
    "@aws-sdk/client-s3": ("cloud_storage", "AWS S3"), "aws-sdk": ("cloud_storage", "AWS SDK"),
    "@google-cloud/storage": ("cloud_storage", "GCS"), "@azure/storage-blob": ("cloud_storage", "Azure Blob"),
    "xml2js": ("xml", "xml2js"), "libxmljs": ("xml", "libxmljs"), "sharp": ("uploads", "sharp"),
}
PY_DEPS = {
    "django": ("django", "Django"), "djangorestframework": ("django", "Django REST Framework"), "flask": ("flask", "Flask"),
    "fastapi": ("fastapi", "FastAPI"), "starlette": ("fastapi", "Starlette"), "sqlalchemy": ("sql", "SQLAlchemy"),
    "psycopg2": ("sql", "psycopg2"), "psycopg": ("sql", "psycopg"), "pymongo": ("mongodb", "PyMongo"),
    "openai": ("llm", "OpenAI SDK"), "anthropic": ("llm", "Anthropic SDK"), "langchain": ("llm", "LangChain"),
    "llama-index": ("llm", "LlamaIndex"), "google-generativeai": ("llm", "Gemini SDK"), "mcp": ("mcp", "MCP SDK"),
    "stripe": ("payments", "Stripe"), "razorpay": ("payments", "Razorpay"), "pyjwt": ("jwt", "PyJWT"),
    "python-jose": ("jwt", "python-jose"), "boto3": ("cloud_storage", "boto3"), "celery": ("queue", "Celery"),
    "requests": ("http_client", "requests"), "httpx": ("http_client", "httpx"), "lxml": ("xml", "lxml"),
    "pillow": ("uploads", "Pillow"), "supabase": ("supabase", "Supabase"), "firebase-admin": ("firebase", "Firebase Admin"),
    "streamlit": ("streamlit", "Streamlit"), "gradio": ("llm", "Gradio"),
}

FILE_MARKERS = {
    "Dockerfile": ("containers", "Docker"), "docker-compose.yml": ("containers", "Docker Compose"),
    "docker-compose.yaml": ("containers", "Docker Compose"), "compose.yaml": ("containers", "Docker Compose"),
    "vercel.json": ("hosting", "Vercel"), "netlify.toml": ("hosting", "Netlify"), "firebase.json": ("firebase", "Firebase Hosting/Rules"),
    "firestore.rules": ("firebase", "Firestore Rules"), "storage.rules": ("firebase", "Firebase Storage Rules"),
    "database.rules.json": ("firebase", "Realtime DB Rules"), "serverless.yml": ("serverless", "Serverless Framework"),
    "wrangler.toml": ("serverless", "Cloudflare Workers"), "wrangler.jsonc": ("serverless", "Cloudflare Workers"),
    "app.yaml": ("hosting", "App Engine"), "Chart.yaml": ("kubernetes", "Helm"), "kustomization.yaml": ("kubernetes", "Kustomize"),
    "wp-config.php": ("wordpress", "WordPress"), "artisan": ("laravel", "Laravel"), "manage.py": ("django", "Django"),
    "AndroidManifest.xml": ("mobile", "Android"), "Info.plist": ("mobile", "iOS"), "pubspec.yaml": ("mobile", "Flutter"),
    "appsscript.json": ("apps_script", "Google Apps Script"), "mcp.json": ("mcp", "MCP config"), ".mcp.json": ("mcp", "MCP config"),
    "CLAUDE.md": ("agent_config", "Claude Code project config"), "AGENTS.md": ("agent_config", "Agent instructions"),
}

FEATURE_CHECKLISTS = {
    "nextjs": ["web-protocol-and-auth.md", "client-side.md", "api-authorization.md", "vibe-coded/authentication.md", "vibe-coded/deployment.md"],
    "react": ["client-side.md"], "vue": ["client-side.md"], "angular": ["client-side.md"], "svelte": ["client-side.md"],
    "sveltekit": ["web-protocol-and-auth.md", "client-side.md", "api-authorization.md"], "nuxt": ["web-protocol-and-auth.md", "client-side.md", "api-authorization.md"],
    "astro": ["client-side.md"], "vite": ["client-side.md", "vibe-coded/secrets-and-env.md"],
    "express": ["web-protocol-and-auth.md", "api-authorization.md"], "nestjs": ["web-protocol-and-auth.md", "api-authorization.md"],
    "fastify": ["web-protocol-and-auth.md", "api-authorization.md"], "koa": ["web-protocol-and-auth.md", "api-authorization.md"],
    "hono": ["web-protocol-and-auth.md", "api-authorization.md"], "remix": ["web-protocol-and-auth.md", "api-authorization.md"],
    "django": ["web-protocol-and-auth.md", "api-authorization.md"], "flask": ["web-protocol-and-auth.md", "api-authorization.md"],
    "fastapi": ["web-protocol-and-auth.md", "api-authorization.md"], "laravel": ["web-protocol-and-auth.md", "api-authorization.md"],
    "wordpress": ["wordpress.md", "web-protocol-and-auth.md", "supply-chain-and-release.md", "file-handling.md"], "rails": ["web-protocol-and-auth.md", "api-authorization.md"],
    "spring": ["web-protocol-and-auth.md", "api-authorization.md"], "aspnet": ["web-protocol-and-auth.md", "api-authorization.md"],
    "supabase": ["baas-database-rules.md", "data-isolation-and-lifecycle.md"], "firebase": ["baas-database-rules.md", "data-isolation-and-lifecycle.md"],
    "convex": ["baas-database-rules.md"], "sql": ["vibe-coded/data-access.md"], "mongodb": ["vibe-coded/data-access.md"], "prisma": ["vibe-coded/data-access.md"],
    "payments": ["payments.md"], "llm": ["ai-llm-and-mcp.md", "vibe-coded/ai-integration.md", "resource-exhaustion.md"], "mcp": ["ai-llm-and-mcp.md"],
    "agent_config": ["ai-llm-and-mcp.md"], "graphql": ["api-authorization.md", "protocols-rpc-and-messaging.md"],
    "websocket": ["client-side.md", "protocols-rpc-and-messaging.md"], "jwt": ["web-protocol-and-auth.md"], "auth": ["web-protocol-and-auth.md"],
    "uploads": ["file-handling.md"], "cloud_storage": ["file-handling.md", "cloud-and-deployment.md"], "xml": ["file-handling.md"],
    "mobile": ["desktop-mobile-and-ipc.md", "vibe-coded/mobile.md"], "desktop": ["desktop-mobile-and-ipc.md", "client-side.md"],
    "containers": ["cloud-and-deployment.md"], "kubernetes": ["cloud-and-deployment.md"], "terraform": ["cloud-and-deployment.md"],
    "serverless": ["cloud-and-deployment.md"], "hosting": ["cloud-and-deployment.md", "vibe-coded/deployment.md"],
    "ci": ["supply-chain-and-release.md"], "queue": ["protocols-rpc-and-messaging.md"], "http_client": [],
    "headless_browser": ["resource-exhaustion.md"], "native": ["memory-safety-and-binary.md"], "apps_script": ["apps-script.md", "web-protocol-and-auth.md"],
    "india_pii": ["india-pii-hotspots.md"], "streamlit": ["web-protocol-and-auth.md"],
}
ALWAYS = ["core-attack-classes.md", "insecure-defaults.md", "secrets-and-config.md", "supply-chain-and-release.md"]

SEMGREP_BY_FEATURE = {
    "JavaScript": ["p/javascript"], "TypeScript": ["p/typescript"], "Python": ["p/python"], "Java": ["p/java"],
    "Go": ["p/golang"], "Ruby": ["p/ruby"], "PHP": ["p/php"], "C#": ["p/csharp"], "Kotlin": ["p/kotlin"],
    "Swift": ["p/swift"], "Rust": ["p/rust"], "Scala": ["p/scala"], "C": ["p/c"], "C++": ["p/c"],
    "nextjs": ["p/nextjs"], "react": ["p/react"], "express": ["p/expressjs"], "django": ["p/django"],
    "flask": ["p/flask"], "fastapi": ["p/fastapi"], "laravel": ["p/laravel"], "spring": ["p/spring"],
    "rails": ["p/ruby"], "jwt": ["p/jwt"], "containers": ["p/dockerfile"], "terraform": ["p/terraform"],
    "kubernetes": ["p/kubernetes"], "ci": ["p/github-actions"], "secrets": ["p/secrets"],
}

INDIA_PII_HINTS = re.compile(
    r"\b(aadhaar|aadhar|adhaar|uidai|pan_?(no|number|card)|pancard|ifsc|uan|esic|pf_?(no|number)|epf|"
    r"form_?16|payslip|salary|ctc|bank_?(account|acc|ac)_?(no|number)?|passport_?(no|number)|voter_?id|gstin)\b",
    re.I,
)

# India-PII hints are only meaningful in the project's OWN code; is_vendor_path()
# (shared in common.py) skips vendored/framework-core/public-plugin paths so a
# dependency's sample data does not raise a false DPDP flag.

ROUTE_HINTS = re.compile(
    r"(app\.(get|post|put|patch|delete)\(|router\.(get|post|put|patch|delete)\(|@(Get|Post|Put|Patch|Delete)Mapping|"
    r"@(app|router)\.(get|post|put|patch|delete)\(|@api_view|path\(|re_path\(|Route::(get|post|put|patch|delete)|"
    r"\[Http(Get|Post|Put|Patch|Delete)|@(Get|Post|Put|Patch|Delete)\(|export (async )?function (GET|POST|PUT|PATCH|DELETE)\b|"
    r"\"use server\"|'use server'|createTRPCRouter|publicProcedure|protectedProcedure)"
)


def _read_json_file(p: Path) -> dict:
    try:
        return json.loads(read_text(p))
    except ValueError:
        return {}


def detect(root: Path, scope: list[str] | None = None) -> dict:
    root = root.resolve()
    langs: Counter = Counter()
    features: dict[str, set[str]] = {}
    manifests: list[str] = []
    route_files: Counter = Counter()
    pii_hits: list[str] = []
    file_count = 0
    extra_ignore = compose_db_dirs(root)

    def add(tag: str, label: str) -> None:
        features.setdefault(tag, set()).add(label)

    for p in walk_files(root, scope, extra_ignore):
        file_count += 1
        name = p.name
        r = rel(root, p)
        lang = EXT_LANG.get(p.suffix.lower())
        if lang:
            langs[lang] += 1
        if lang in ("C", "C++", "Rust"):
            add("native", lang)
        if name in FILE_MARKERS:
            add(*FILE_MARKERS[name])
        if p.suffix == ".tf":
            add("terraform", "Terraform")
        if r.startswith(".github/workflows/") or name in (".gitlab-ci.yml", "Jenkinsfile", "azure-pipelines.yml", "bitbucket-pipelines.yml"):
            add("ci", "CI/CD pipelines")
        if r.startswith("supabase/") or "/supabase/migrations/" in r:
            add("supabase", "Supabase (migrations/policies in repo)")
        # Do NOT read file contents for vendored / public-plugin paths. On a 10k-file
        # WordPress install, reading every Elementor/RevSlider/W3TC file for route and
        # PII hints is what made `init --wp` take minutes. Extension-based language
        # counts and name-based markers (above) are kept; route/PII/manifest parsing
        # (below, which read the file) is skipped for these dependency paths.
        if is_vendor_path(r):
            continue
        if p.suffix in (".yaml", ".yml"):
            head = read_text(p)[:2000]
            if "apiVersion:" in head and "kind:" in head:
                add("kubernetes", "Kubernetes manifests")
        if p.suffix in (".csproj", ".sln"):
            add("aspnet", ".NET")
        if name == "package.json":
            manifests.append(r)
            data = _read_json_file(p)
            deps = {**data.get("dependencies", {}), **data.get("devDependencies", {})}
            for d in deps:
                hit = NODE_DEPS.get(d.lower())
                if hit:
                    add(*hit)
        elif name in ("requirements.txt", "pyproject.toml", "Pipfile", "setup.py", "setup.cfg"):
            manifests.append(r)
            txt = read_text(p).lower()
            for d, hit in PY_DEPS.items():
                if re.search(rf"(^|[\s\"'\[,]){re.escape(d)}([\s=<>~!\[\"',;]|$)", txt, re.M):
                    add(*hit)
        elif name == "composer.json":
            manifests.append(r)
            data = _read_json_file(p)
            req = {**data.get("require", {}), **data.get("require-dev", {})}
            if any(k.startswith("laravel/") for k in req):
                add("laravel", "Laravel")
            if any(k.startswith("symfony/") for k in req):
                add("symfony", "Symfony")
        elif name in ("pom.xml", "build.gradle", "build.gradle.kts"):
            manifests.append(r)
            if "spring-boot" in read_text(p) or "org.springframework" in read_text(p):
                add("spring", "Spring Boot")
        elif name == "Gemfile":
            manifests.append(r)
            if "rails" in read_text(p):
                add("rails", "Ruby on Rails")
        elif name == "go.mod":
            manifests.append(r)
            txt = read_text(p)
            for mod, label in (("gin-gonic/gin", "Gin"), ("labstack/echo", "Echo"), ("gofiber/fiber", "Fiber"), ("go-chi/chi", "chi")):
                if mod in txt:
                    add("go_web", label)
        elif name in ("Cargo.toml", "pubspec.yaml", "Package.swift", "mix.exs"):
            manifests.append(r)

        if lang and lang not in ("SQL", "Terraform"):
            txt = read_text(p)
            n = len(ROUTE_HINTS.findall(txt))
            if n:
                route_files[r] = n
            if len(pii_hits) < 40 and not is_vendor_path(r) and INDIA_PII_HINTS.search(txt):
                pii_hits.append(r)
        elif p.suffix.lower() in (".sql", ".prisma", ".graphql"):
            if len(pii_hits) < 40 and not is_vendor_path(r) and INDIA_PII_HINTS.search(read_text(p)):
                pii_hits.append(r)

    if pii_hits:
        add("india_pii", "Indian PII fields (Aadhaar/PAN/bank/salary/UAN)")
    if (root / ".git").exists():
        add("git", "Git history present")

    tags = set(features)
    checklists = list(ALWAYS)
    for t in sorted(tags):
        for c in FEATURE_CHECKLISTS.get(t, []):
            if c not in checklists:
                checklists.append(c)
    if any(t in tags for t in ("express", "nestjs", "fastify", "django", "flask", "fastapi", "laravel", "rails", "spring", "aspnet", "go_web", "nextjs", "supabase", "firebase")):
        if "data-isolation-and-lifecycle.md" not in checklists:
            checklists.append("data-isolation-and-lifecycle.md")

    semgrep = ["p/default", "p/owasp-top-ten", "p/secrets"]
    for key in list(langs) + sorted(tags):
        for cfg in SEMGREP_BY_FEATURE.get(key, []):
            if cfg not in semgrep:
                semgrep.append(cfg)

    return {
        "target": str(root),
        "files_scanned": file_count,
        "languages": dict(langs.most_common()),
        "features": {k: sorted(v) for k, v in sorted(features.items())},
        "manifests": sorted(manifests),
        "likely_entry_files": [f for f, _ in route_files.most_common(40)],
        "india_pii_files": pii_hits,
        "suggested_checklists": ["checklists/" + c for c in checklists],
        "semgrep_configs": semgrep,
        "note": "Heuristic hints for Phase 1. Recon confirms or corrects them.",
    }
