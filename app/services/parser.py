import re
from dataclasses import dataclass
from datetime import datetime

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
    host: str|None
    process: str|None
    message: str
    normalized: str
    os_type: str
    cluster_id: int = None
    timestamp: str = None
    timestamp_dt: datetime = None
    time_diff: float = None

    def dict(self):
        return {
            "raw": self.raw,
            "timestamp": self.timestamp,
            "timestamp_dt": self.timestamp_dt.isoformat() if self.timestamp_dt else None,
            "host": self.host,
            "process": self.process,
            "message": self.message,
            "normalized": self.normalized,
            "os_type": self.os_type,
            "cluster_id": self.cluster_id,
            "time_diff": self.time_diff,
        }


class SyslogParser:
    def __init__(self):
        self.current_year = datetime.now().year

    def parse_text(self, text: str) -> list[SyslogEntry]:
        entries = []
        for raw_line in text.splitlines():
            raw_line = raw_line.strip()
            if not raw_line:
                continue
            entry = self.parse_line(raw_line)
            if entry:
                entries.append(entry)
        
        entries = self.calculate_time_diffs(entries)
        return entries

    def parse_line(self, raw_line: str) -> SyslogEntry|None:
        match = LINUX_PATTERN.match(raw_line)
        if match:
            timestamp_str = match.group("timestamp")
            timestamp_dt = self._parse_linux_timestamp(timestamp_str)
            message = match.group("message")
            return SyslogEntry(
                raw=raw_line,
                timestamp=timestamp_str,
                timestamp_dt=timestamp_dt,
                host=match.group("host"),
                process=match.group("process"),
                message=message,
                normalized=self.normalize(message),
                os_type="linux",
            )

        match = WINDOWS_PATTERN.match(raw_line)
        if match:
            timestamp_str = match.group("timestamp")
            timestamp_dt = self._parse_windows_timestamp(timestamp_str)
            message = match.group("message")
            return SyslogEntry(
                raw=raw_line,
                timestamp=timestamp_str,
                timestamp_dt=timestamp_dt,
                host=None,
                process=match.group("process"),
                message=message,
                normalized=self.normalize(message),
                os_type="windows",
            )

        return None

    def _parse_linux_timestamp(self, timestamp_str: str) -> datetime|None:
        """Парсит Linux timestamp: 'Jan 12 14:30:45'"""
        try:
            months = {
                'Jan': 1, 'Feb': 2, 'Mar': 3, 'Apr': 4, 'May': 5, 'Jun': 6,
                'Jul': 7, 'Aug': 8, 'Sep': 9, 'Oct': 10, 'Nov': 11, 'Dec': 12
            }
            parts = timestamp_str.split()
            if len(parts) == 3:
                month_name, day_str, time_str = parts
                month = months.get(month_name, 1)
                day = int(day_str)
                hour, minute, second = map(int, time_str.split(':'))
                year = self.current_year
                
                current_month = datetime.now().month
                if month > current_month:
                    year -= 1
                
                return datetime(year, month, day, hour, minute, second)
        except Exception:
            pass
        return None

    def _parse_windows_timestamp(self, timestamp_str: str) -> datetime|None:
        """Парсит Windows timestamp: '2024-01-12 14:30:45'"""
        try:
            return datetime.strptime(timestamp_str, "%Y-%m-%d %H:%M:%S")
        except Exception:
            return None

    def calculate_time_diffs(self, entries: list[SyslogEntry]) -> list[SyslogEntry]:
        """Вычисляет разницу во времени между последовательными логами"""
        if not entries:
            return entries
        
        prev_dt = None
        for entry in entries:
            if entry.timestamp_dt:
                if prev_dt:
                    entry.time_diff = (entry.timestamp_dt - prev_dt).total_seconds()
                else:
                    entry.time_diff = 0.0  # Для первого лога
                prev_dt = entry.timestamp_dt
            else:
                entry.time_diff = None
        
        return entries

    def normalize(self, message: str) -> str:
        text = message.lower()
        text = re.sub(r"\b(?:\d{1,3}\.){3}\d{1,3}\b", "", text)
        text = re.sub(r"\b[0-9a-f]{4,}\b", "", text)
        text = re.sub(r"\d+", "", text)
        text = re.sub(r"[^a-z0-9 ]+", " ", text)
        text = re.sub(r"\s+", " ", text).strip()
        return text
