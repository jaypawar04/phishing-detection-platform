import ast

from fastapi import FastAPI, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel, HttpUrl
from sqlalchemy.orm import Session

from database import Base, SessionLocal, engine
from detector import analyze_url
from models import Alert, Scan


# Create database tables
Base.metadata.create_all(bind=engine)


# =========================================================
# APPLICATION
# =========================================================

app = FastAPI(
    title="Phishing Detection Platform",
    description=(
        "Cybersecurity platform for phishing URL detection "
        "and SOC-style threat monitoring."
    ),
    version="2.0.0",
)


# =========================================================
# CORS
# =========================================================

app.add_middleware(
    CORSMiddleware,
    allow_origins=[
        "http://localhost:5173",
        "http://127.0.0.1:5173",
    ],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)


# =========================================================
# REQUEST MODEL
# =========================================================

class ScanRequest(BaseModel):
    url: HttpUrl


# =========================================================
# HELPERS
# =========================================================

def parse_reasons(reasons):
    """
    Handles both:
    - New JSON/list format
    - Old database rows stored as strings
    """

    if not reasons:
        return []

    if isinstance(reasons, list):
        return reasons

    if isinstance(reasons, str):
        try:
            parsed = ast.literal_eval(reasons)
            return parsed if isinstance(parsed, list) else []
        except (ValueError, SyntaxError):
            return []

    return []


def get_alert_severity(risk_score: int) -> str:
    if risk_score >= 80:
        return "critical"

    if risk_score >= 50:
        return "high"

    if risk_score >= 20:
        return "medium"

    return "low"


def create_alert(
    db: Session,
    scan: Scan,
    reasons,
):
    """
    Create a SOC alert for non-legitimate scans.
    """

    if scan.verdict == "legitimate":
        return None

    severity = get_alert_severity(scan.risk_score)

    if severity == "critical":
        title = "Critical phishing threat detected"

    elif severity == "high":
        title = "High-risk URL detected"

    elif severity == "medium":
        title = "Suspicious URL detected"

    else:
        title = "Low-risk suspicious activity detected"

    description = (
        f"URL {scan.url} generated a risk score of "
        f"{scan.risk_score}/100 with verdict "
        f"'{scan.verdict}'."
    )

    alert = Alert(
        scan_id=scan.id,
        severity=severity,
        title=title,
        status="open",
        description=description,
    )

    db.add(alert)

    return alert


# =========================================================
# HEALTH CHECK
# =========================================================

@app.get("/")
def root():
    return {
        "project": "Phishing Detection Platform",
        "status": "online",
        "version": "2.0.0",
        "message": "SOC-enabled backend is running successfully",
    }


@app.get("/health")
def health_check():
    return {
        "status": "healthy",
    }


# =========================================================
# SCANNING
# =========================================================

@app.post("/api/v1/scan")
def scan_url(request: ScanRequest):
    db: Session = SessionLocal()

    try:
        url = str(request.url)

        result = analyze_url(url)

        scan = Scan(
            url=url,
            verdict=result["verdict"],
            risk_score=result["risk_score"],
            reasons=result["reasons"],
        )

        db.add(scan)
        db.flush()

        alert = create_alert(
            db=db,
            scan=scan,
            reasons=result["reasons"],
        )

        db.commit()
        db.refresh(scan)

        if alert:
            db.refresh(alert)

        return {
            "id": scan.id,
            "url": scan.url,
            "risk_score": scan.risk_score,
            "verdict": scan.verdict,
            "reasons": result["reasons"],
            "features": result["features"],
            "alert": (
                {
                    "id": alert.id,
                    "severity": alert.severity,
                    "title": alert.title,
                    "status": alert.status,
                }
                if alert
                else None
            ),
            "scanned_at": scan.scanned_at,
        }

    except Exception as exc:
        db.rollback()

        raise HTTPException(
            status_code=500,
            detail="An error occurred while scanning the URL.",
        ) from exc

    finally:
        db.close()


# =========================================================
# SCAN HISTORY
# =========================================================

@app.get("/api/v1/scans")
def get_scans():
    db: Session = SessionLocal()

    try:
        scans = (
            db.query(Scan)
            .order_by(Scan.scanned_at.desc())
            .all()
        )

        return [
            {
                "id": scan.id,
                "url": scan.url,
                "risk_score": scan.risk_score,
                "verdict": scan.verdict,
                "reasons": parse_reasons(scan.reasons),
                "scanned_at": scan.scanned_at,
            }
            for scan in scans
        ]

    finally:
        db.close()


# =========================================================
# GET SCAN DETAILS
# =========================================================

@app.get("/api/v1/scans/{scan_id}")
def get_scan_details(scan_id: int):
    db: Session = SessionLocal()

    try:
        scan = (
            db.query(Scan)
            .filter(Scan.id == scan_id)
            .first()
        )

        if scan is None:
            raise HTTPException(
                status_code=404,
                detail=f"Scan with ID {scan_id} not found.",
            )

        return {
            "id": scan.id,
            "url": scan.url,
            "risk_score": scan.risk_score,
            "verdict": scan.verdict,
            "reasons": parse_reasons(scan.reasons),
            "scanned_at": scan.scanned_at,
        }

    finally:
        db.close()


# =========================================================
# DELETE SCAN
# =========================================================

@app.delete("/api/v1/scans/{scan_id}")
def delete_scan(scan_id: int):
    db: Session = SessionLocal()

    try:
        scan = (
            db.query(Scan)
            .filter(Scan.id == scan_id)
            .first()
        )

        if scan is None:
            raise HTTPException(
                status_code=404,
                detail=f"Scan with ID {scan_id} not found.",
            )

        # Delete associated SOC alerts first
        db.query(Alert).filter(
            Alert.scan_id == scan_id
        ).delete()

        # Delete scan record
        db.delete(scan)

        db.commit()

        return {
            "message": "Scan deleted successfully.",
            "scan_id": scan_id,
        }

    except HTTPException:
        raise

    except Exception as exc:
        db.rollback()

        raise HTTPException(
            status_code=500,
            detail="An error occurred while deleting the scan.",
        ) from exc

    finally:
        db.close()


# =========================================================
# SOC ALERTS
# =========================================================

@app.get("/api/v1/alerts")
def get_alerts():
    db: Session = SessionLocal()

    try:
        alerts = (
            db.query(Alert)
            .order_by(Alert.created_at.desc())
            .all()
        )

        return [
            {
                "id": alert.id,
                "scan_id": alert.scan_id,
                "severity": alert.severity,
                "title": alert.title,
                "status": alert.status,
                "description": alert.description,
                "created_at": alert.created_at,
            }
            for alert in alerts
        ]

    finally:
        db.close()


@app.get("/api/v1/alerts/{alert_id}")
def get_alert(alert_id: int):
    db: Session = SessionLocal()

    try:
        alert = (
            db.query(Alert)
            .filter(Alert.id == alert_id)
            .first()
        )

        if alert is None:
            raise HTTPException(
                status_code=404,
                detail=f"Alert with ID {alert_id} not found.",
            )

        return {
            "id": alert.id,
            "scan_id": alert.scan_id,
            "severity": alert.severity,
            "title": alert.title,
            "status": alert.status,
            "description": alert.description,
            "created_at": alert.created_at,
        }

    finally:
        db.close()


# =========================================================
# SOC STATISTICS
# =========================================================

@app.get("/api/v1/soc/stats")
def get_soc_stats():
    db: Session = SessionLocal()

    try:
        alerts = db.query(Alert).all()

        return {
            "total_alerts": len(alerts),

            "open_alerts": sum(
                1
                for alert in alerts
                if alert.status == "open"
            ),

            "critical_alerts": sum(
                1
                for alert in alerts
                if alert.severity == "critical"
            ),

            "high_alerts": sum(
                1
                for alert in alerts
                if alert.severity == "high"
            ),

            "medium_alerts": sum(
                1
                for alert in alerts
                if alert.severity == "medium"
            ),

            "low_alerts": sum(
                1
                for alert in alerts
                if alert.severity == "low"
            ),
        }

    finally:
        db.close()