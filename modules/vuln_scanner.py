import asyncio
import re
import json
import aiohttp
from lxml import html
import sys
from typing import Dict, List, Optional, Tuple
from dataclasses import dataclass
from datetime import datetime

@dataclass
class Vulnerability:
    title: str
    url: str
    date: str
    source: str

class VulnerabilityScanner:
    def __init__(self):
        self.exploitdb_search_url = "https://www.exploit-db.com/search?query={query}"
        self.nvd_search_url = "https://services.nvd.nist.gov/rest/json/cves/2.0?keywordSearch={query}"
        self.headers = {
            "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36"
        }

    def extract_service_version(self, service_info: str):
        # 例: "vsftpd 2.3.4" → ("vsftpd", "2.3.4")
        patterns = [
            r'(\w+)\s+(\d+\.\d+(?:\.\d+)?)',  # Apache 2.4.41
            r'(\w+)/(\d+\.\d+(?:\.\d+)?)',      # nginx/1.18.0
            r'(\w+)-(\d+\.\d+(?:\.\d+)?)',      # OpenSSH-8.2
        ]
        for pat in patterns:
            m = re.search(pat, service_info)
            if m:
                return m.group(1), m.group(2)
        return service_info, None

    async def search_exploitdb(self, service: str, version: Optional[str]) -> List[Vulnerability]:
        query = service if not version else f"{service} {version}"
        url = self.exploitdb_search_url.format(query=query.replace(' ', '+'))
        vulns = []
        async with aiohttp.ClientSession() as session:
            async with session.get(url) as resp:
                if resp.status != 200:
                    print(f"[ExploitDB] HTTPエラー: {resp.status}")
                    return []
                text = await resp.text()
                tree = html.fromstring(text)
                rows = tree.xpath('//table[contains(@class,"exploit-list")]//tr')
                for row in rows[1:]:  # skip header
                    cols = row.xpath('.//td')
                    if len(cols) < 7:
                        continue
                    date = cols[1].text_content().strip()
                    title_elem = cols[4].xpath('.//a')
                    if not title_elem:
                        continue
                    title = title_elem[0].text_content().strip()
                    href = title_elem[0].get('href')
                    vuln_url = f"https://www.exploit-db.com{href}" if href else ""
                    vulns.append(Vulnerability(
                        title=title,
                        url=vuln_url,
                        date=date,
                        source="Exploit-DB"
                    ))
        return vulns

    async def search_nvd(self, service: str, version: Optional[str]) -> List[Vulnerability]:
        query = service if not version else f"{service} {version}"
        url = self.nvd_search_url.format(query=query)
        vulns = []
        async with aiohttp.ClientSession() as session:
            async with session.get(url) as resp:
                if resp.status != 200:
                    print(f"[NVD] HTTPエラー: {resp.status}")
                    return []
                try:
                    data = await resp.json()
                except Exception as e:
                    print(f"[NVD] JSONパースエラー: {e}")
                    return []
                for item in data.get('vulnerabilities', []):
                    cve = item.get('cve', {})
                    title = cve.get('descriptions', [{}])[0].get('value', '')
                    cve_id = cve.get('id', '')
                    vuln_url = f"https://nvd.nist.gov/vuln/detail/{cve_id}" if cve_id else ""
                    published = cve.get('published', '')
                    vulns.append(Vulnerability(
                        title=title,
                        url=vuln_url,
                        date=published,
                        source="NVD"
                    ))
        return vulns

    async def scan(self, service_info: str) -> List[Vulnerability]:
        service, version = self.extract_service_version(service_info)
        results = []
        exploitdb_vulns = await self.search_exploitdb(service, version)
        nvd_vulns = await self.search_nvd(service, version)
        results.extend(exploitdb_vulns)
        results.extend(nvd_vulns)
        return results

    def format_vulns(self, vulns: List[Vulnerability]) -> str:
        if not vulns:
            return (
                "脆弱性情報が見つかりませんでした。\n"
                "※ このメッセージは以下の理由で表示される可能性があります：\n"
                "1. データベースに登録されていない\n"
                "2. バージョン情報が正確でない\n"
                "3. 脆弱性が存在しない\n"
                "より詳細な調査が必要な場合は、NSEスクリプトを使用することをお勧めします。"
            )
        msg = "\n[脆弱性情報]\n"
        for v in vulns:
            msg += f"- [{v.source}] {v.title} ({v.date})\n  {v.url}\n"
        return msg 