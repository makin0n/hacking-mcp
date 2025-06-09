import os
from datetime import datetime

class ReportManager:
    def __init__(self, target: str, base_dir: str = "reports"):
        self.target = target.replace('://', '_').replace('/', '_')
        self.timestamp = datetime.now().strftime("%Y-%m-%d_%H-%M-%S")
        self.project_name = f"{self.target}_{self.timestamp}"
        
        self.project_dir = os.path.join(base_dir, self.project_name)
        self.ss_dir = os.path.join(self.project_dir, "screenshots")
        self.report_path = os.path.join(self.project_dir, "report.md")

        # プロジェクトディレクトリとスクリーンショット用サブディレクトリを作成
        os.makedirs(self.ss_dir, exist_ok=True)
        self._init_report()

    def _init_report(self):
        """レポートファイルの初期化"""
        header = f"# Reconnaissance Report for {self.target}\n"
        header += f"Scan Date: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n\n"
        self.write(header)

    def write(self, content: str):
        """レポートファイルに追記"""
        with open(self.report_path, "a", encoding="utf-8") as f:
            f.write(content + "\n")

    def add_section(self, title: str, content: str):
        """セクションとして追記"""
        section_content = f"## {title}\n\n"
        section_content += "```\n"
        section_content += content
        section_content += "\n```\n\n"
        self.write(section_content)

    def add_screenshot(self, service_url: str, image_path: str):
        """スクリーンショットをレポートに埋め込む"""
        relative_path = os.path.join("screenshots", os.path.basename(image_path))
        ss_content = f"### Screenshot for {service_url}\n"
        ss_content += f"![{service_url}]({relative_path})\n\n"
        self.write(ss_content)