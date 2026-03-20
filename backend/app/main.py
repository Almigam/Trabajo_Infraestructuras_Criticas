from fastapi import FastAPI, Depends
from fastapi.middleware.cors import CORSMiddleware
from sqlalchemy.orm import Session
from app.database import init_db, get_db, ScanResult
from app.analyzers.fr1_iac import run_all_fr1_checks

app = FastAPI(
    title="IEC 62443-3-3 Analyzer",
    description="Analizador de cumplimiento para sistemas de control industrial",
    version="0.1.0"
)

# CORS para el frontend React
app.add_middleware(
    CORSMiddleware,
    allow_origins=["http://localhost:5173", "http://localhost:3000"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

@app.on_event("startup")
def startup():
    init_db()

@app.get("/")
def root():
    return {"message": "IEC 62443-3-3 Analyzer API", "status": "running"}

@app.get("/api/scan/fr1")
def scan_fr1(db: Session = Depends(get_db)):
    """Ejecuta análisis del FR1 - Control de Identificación y Autenticación"""
    results = run_all_fr1_checks()
    
    # Guardar en base de datos
    for r in results:
        db_result = ScanResult(**r)
        db.add(db_result)
    db.commit()
    
    return {
        "fr": "FR1 - Control de Identificación y Autenticación (IAC)",
        "total_checks": len(results),
        "passed": sum(1 for r in results if r["status"] == "PASS"),
        "failed": sum(1 for r in results if r["status"] == "FAIL"),
        "warnings": sum(1 for r in results if r["status"] == "WARNING"),
        "results": results
    }

@app.get("/api/scan/all")
def scan_all(db: Session = Depends(get_db)):
    """Ejecuta análisis completo de todos los FR disponibles"""
    all_results = run_all_fr1_checks()
    # Aquí irán fr2, fr3... cuando los implementéis
    
    for r in all_results:
        db.add(ScanResult(**r))
    db.commit()
    
    return {
        "total_checks": len(all_results),
        "passed": sum(1 for r in all_results if r["status"] == "PASS"),
        "failed": sum(1 for r in all_results if r["status"] == "FAIL"),
        "warnings": sum(1 for r in all_results if r["status"] == "WARNING"),
        "results": all_results
    }

@app.get("/api/history")
def get_history(db: Session = Depends(get_db)):
    """Devuelve el historial de análisis"""
    results = db.query(ScanResult).order_by(ScanResult.timestamp.desc()).limit(50).all()
    return results