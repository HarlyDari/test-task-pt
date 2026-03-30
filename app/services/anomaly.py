from app.services.parser import SyslogEntry
from app.models.cluster_response import ClusterResult


class AnomalyDetector:
    def detect(self, entries: list[SyslogEntry], clusters: list[ClusterResult]) -> list[SyslogEntry]:
        anomaly_entries: list[SyslogEntry] = []
        small_clusters = {cluster.cluster_id for cluster in clusters if cluster.size == 1}
        for entry in entries:
            if entry.cluster_id == -1 or entry.cluster_id in small_clusters:
                anomaly_entries.append(entry)
        return anomaly_entries
