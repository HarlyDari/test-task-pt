from fastapi import FastAPI, HTTPException, UploadFile, File
from fastapi.responses import JSONResponse
from app.services.parser import SyslogParser
from app.services.clusterer import LogClusterer
from app.services.anomaly import AnomalyDetector
import io

app = FastAPI(
    title="LogHub Event Cluster Service",
    description="FastAPI сервис для кластеризации Linux syslog событий и выявления аномалий.",
    version="0.1.0",
)

parser = SyslogParser()
clusterer = LogClusterer()
anomaly_detector = AnomalyDetector()


@app.get("/health")
def health_check():
    return {"status": "ok"}


@app.post("/analyze")
async def analyze_logs(file: UploadFile = File(None), raw_logs: str = None):
    if file is None and raw_logs is None:
        raise HTTPException(status_code=400, detail="Provide raw_logs or upload a file.")

    if file is not None:
        raw_bytes = await file.read()
        try:
            content = raw_bytes.decode("utf-8")
        except UnicodeDecodeError:
            raise HTTPException(status_code=400, detail="Uploaded file must be UTF-8 encoded text.")
    else:
        content = raw_logs

    entries = parser.parse_text(content)
    if not entries:
        raise HTTPException(status_code=400, detail="No valid syslog entries were parsed.")

    cluster_result = clusterer.cluster(entries)
    anomalies = anomaly_detector.detect(entries, cluster_result)

    return JSONResponse(
        content={
            "entries": [entry.dict() for entry in entries],
            "clusters": [cluster.dict() for cluster in cluster_result],
            "anomalies": [entry.dict() for entry in anomalies],
        }
    )


@app.get("/sample")
def analyze_sample():
    try:
        with open("data/Linux_2k.log", "r", encoding="utf-8") as stream:
            sample_text = stream.read()
    except FileNotFoundError:
        raise HTTPException(status_code=500, detail="Linux dataset not found.")
    entries = parser.parse_text(sample_text)

    try:
        with open("data/Windows_2k.log", "r", encoding="utf-8") as stream:
            sample_text = stream.read()
    except FileNotFoundError:
        raise HTTPException(status_code=500, detail="Windows dataset not found.")
    for enter in parser.parse_text(sample_text):
        entries.append(enter)
    
    cluster_result = clusterer.cluster(entries)
    anomalies = anomaly_detector.detect(entries, cluster_result)

    return {
        "source": "data/sample_syslog.log",
        "entry_count": len(entries),
        "clusters": [cluster.dict() for cluster in cluster_result],
        "anomalies": [entry.dict() for entry in anomalies],
    }
