from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.ensemble import IsolationForest
from app.services.parser import SyslogEntry
from app.models.cluster_response import ClusterResult


class LogClusterer:
    def cluster(self, entries: list[SyslogEntry]) -> list[ClusterResult]:
        messages = [entry.normalized for entry in entries]
        vectorizer = TfidfVectorizer(stop_words="english", ngram_range=(1, 2), min_df=1)
        X = vectorizer.fit_transform(messages)

        if len(entries) < 2:
            for entry in entries:
                entry.cluster_id = 0
            return [ClusterResult(cluster_id=0, size=len(entries), examples=[entries[0].message if entries else ""])]

        model = IsolationForest(n_estimators=200, contamination=0.1, random_state=42, n_jobs=-1)
        labels = model.fit_predict(X)

        clusters: dict[int, list[SyslogEntry]] = {}
        for entry, label in zip(entries, labels):
            entry.cluster_id = int(label)
            clusters.setdefault(int(label), []).append(entry)

        result = []
        for cluster_id, group in sorted(clusters.items(), key=lambda item: item[0]):
            examples = [entry.message for entry in group[:3]]
            size = len(group)
            result.append(ClusterResult(cluster_id=cluster_id, size=size, examples=examples))

        return result
