from dataclasses import dataclass


@dataclass
class ClusterResult:
    cluster_id: int
    size: int
    examples: list[str]

    def dict(self):
        return {
            "cluster_id": self.cluster_id,
            "size": self.size,
            "examples": self.examples,
        }
