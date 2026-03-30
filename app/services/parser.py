import re
from dataclasses import dataclass
from typing import Optional

LINUX_PATTERN = re.compile(
    r"^(?P<timestamp>[A-Z][a-z]{2} +\d{1,2} \d{2}:\d{2}:\d{2}) "
    r"(?P<host>[^ ]+) "
    r"(?P<process>[^\[:]+(?:\([^\)]+\))?)(?:\[\d+\])?: (?P<message>.+)$"
)

WINDOWS_PATTERN = re.compile(
    r"^(?P<timestamp>\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2}),\s*"
    r"(?P<level>\w+)\s+"
    r"(?P<process>\w+)\s+"
    r"(?P<message>.+)$"
)


@dataclass
class SyslogEntry:
    raw: str
    timestamp: Optional[str]
    host: Optional[str]
    process: Optional[str]
    message: str
    normalized: str
    os_type: str
    cluster_id: Optional[int] = None

    def dict(self):
        return {
            "raw": self.raw,
            "timestamp": self.timestamp,
            "host": self.host,
            "process": self.process,
            "message": self.message,
            "normalized": self.normalized,
            "os_type": self.os_type,
            "cluster_id": self.cluster_id,
        }


class SyslogParser:
    def parse_text(self, text: str) -> list[SyslogEntry]:
        entries = []
        for raw_line in text.splitlines():
            raw_line = raw_line.strip()
            if not raw_line:
                continue
            entry = self.parse_line(raw_line)
            if entry:
                entries.append(entry)
        return entries

    def parse_line(self, raw_line: str) -> Optional[SyslogEntry]:

        match = LINUX_PATTERN.match(raw_line)
        if match:
            message = match.group("message")
            return SyslogEntry(
                raw=raw_line,
                timestamp=match.group("timestamp"),
                host=match.group("host"),
                process=match.group("process"),
                message=message,
                normalized=self.normalize(message),
                os_type="linux",
            )

        match = WINDOWS_PATTERN.match(raw_line)
        if match:
            message = match.group("message")
            return SyslogEntry(
                raw=raw_line,
                timestamp=match.group("timestamp"),
                host=None,
                process=match.group("process"),
                message=message,
                normalized=self.normalize(message),
                os_type="windows",
            )

        return None

    def normalize(self, message: str) -> str:
        text = message.lower()
        text = re.sub(r"\b(?:\d{1,3}\.){3}\d{1,3}\b", "", text)
        text = re.sub(r"\b[0-9a-f]{4,}\b", "", text)
        text = re.sub(r"\d+", "", text)
        text = re.sub(r"[^a-z0-9 ]+", " ", text)
        text = re.sub(r"\s+", " ", text).strip()
        return text