import re
from datetime import datetime
import httpx
import asyncio

import os
from dotenv import load_dotenv

# Подгружаем переменные окружения, если это отдельный скрипт
load_dotenv()

# Достаем токен
GITHUB_TOKEN = str(os.getenv("GITHUB_TOKEN"))

# Формируем заголовки, которые требует GitHub API
HEADERS = {
    "Authorization": f"Bearer {GITHUB_TOKEN}",
    "Accept": "application/vnd.github.v3+json",
    "X-GitHub-Api-Version": "2022-11-28"
}


def extract_repo_and_commit(url: str) -> tuple[str, str, str] | None:
    """
    Парсит URL вида https://github.com/owner/repo/commit/hash
    и возвращает (owner, repo, commit_hash)
    """
    pattern = r"github\.com/([^/]+)/([^/]+)/commit/([a-f0-9]+)"
    match = re.search(pattern, url)
    if match:
        owner, repo, commit_hash = match.groups()
        repo = repo.replace(".git", "")
        return owner, repo, commit_hash
    return None


async def fetch_commit_date(client: httpx.AsyncClient, owner: str, repo: str, commit_hash: str) -> datetime | None:
    """
    Асинхронно запрашивает дату фикса через GitHub REST API.
    """
    api_url = f"https://api.github.com/repos/{owner}/{repo}/commits/{commit_hash}"

    try:
        response = await client.get(api_url)

        # Обработка лимитов GitHub (Rate Limiting)
        if response.status_code == 403 and "X-RateLimit-Remaining" in response.headers:
            if response.headers["X-RateLimit-Remaining"] == "0":
                reset_time = float(response.headers["X-RateLimit-Reset"])
                sleep_duration = max(0, reset_time - datetime.now().timestamp())
                print(f"[!] Достигнут лимит API. Пауза на {sleep_duration} секунд...")
                await asyncio.sleep(sleep_duration + 1)
                return await fetch_commit_date(client, owner, repo, commit_hash)  # Retry

        response.raise_for_status()
        data = response.json()

        # Берем дату, когда коммит был реально записан в историю (committer date),
        # так как author date может быть сфальсифицирована или взята из старой ветки.
        date_str = data["commit"]["committer"]["date"]

        # Парсим ISO-8601 дату (пример: 2024-05-18T15:00:00Z)
        # Python 3.11+ умеет парсить Z на конце через fromisoformat
        return datetime.fromisoformat(date_str.replace('Z', '+00:00'))

    except httpx.HTTPStatusError as e:
        print(f"[-] Ошибка HTTP {e.response.status_code} для {api_url}")
    except Exception as e:
        print(f"[-] Ошибка парсинга {api_url}: {e}")


async def enrich_vulnerability_data() -> None:
    """
    Пример оркестратора
    """
    osv_fix_references = [
        "https://github.com/sstar1475/ai360_osv_insights/commit/222d98c48ee7184f7b4a2418b3d2eb1434c2dcda"
    ]

    # Используем один AsyncClient для переиспользования TCP-соединений (Connection Pooling)
    async with httpx.AsyncClient(headers=HEADERS, timeout=10.0) as client:

        tasks = []
        for ref in osv_fix_references:
            parsed = extract_repo_and_commit(ref)
            if parsed:
                owner, repo, commit = parsed
                # Создаем корутины, но не ждем их по одной
                tasks.append(fetch_commit_date(client, owner, repo, commit))

        # Запускаем запросы конкурентно (пачками).
        # Осторожно: не запускай больше 50-100 штук за раз, иначе GitHub забанит по IP за спам.
        print(f"Начинаем сбор дат для {len(tasks)} коммитов...")
        results = await asyncio.gather(*tasks)

        for ref, date in zip(osv_fix_references, results):
            if date:
                print(f"[+] Фикс найден: {date.strftime('%Y-%m-%d %H:%M:%S')} | URL: {ref}")
            else:
                print(f"[-] Не удалось получить дату для {ref}")


if __name__ == "__main__":
    asyncio.run(enrich_vulnerability_data())
