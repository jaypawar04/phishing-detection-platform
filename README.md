# PhishGuard — Phishing Detection & SOC Monitoring Platform

A cybersecurity platform designed to analyze URLs, detect potential phishing threats, generate security alerts, maintain scan history, and provide SOC-style monitoring capabilities.

This project demonstrates practical knowledge of phishing detection, threat analysis, REST API development, database integration, and security monitoring workflows.

---

## Disclaimer

This project is intended for educational, research, and cybersecurity awareness purposes only.

Do not use this platform to scan URLs without proper authorization.

The detection results are intended for demonstration and learning purposes and should not be considered a replacement for professional threat intelligence or security analysis.

---

## Project Overview

Phishing attacks are commonly used to steal login credentials, financial information, and personal data.

PhishGuard provides a security-focused platform for analyzing suspicious URLs and identifying potential phishing indicators.

The application combines a Python-based detection engine, FastAPI backend, React frontend, and database-driven alert management system.

The platform is designed as a practical cybersecurity project demonstrating how security detection workflows can be integrated into a web application.

---

## Features

### URL Security Analysis

- Analyze submitted URLs for suspicious characteristics.
- Detect potential phishing indicators.
- Generate a risk score.
- Classify URLs based on detected risk.
- Display reasons contributing to the risk assessment.

### SOC Monitoring

- Generate security alerts from scan results.
- View and manage security alerts.
- Display alert severity and detection information.
- Provide a centralized monitoring dashboard.

### Scan Management

- Store scan history in the database.
- View detailed scan results.
- Delete scan records when required.
- Track scan timestamps and verdicts.

### Reporting

- Generate scan reports.
- Export scan results as PDF documents.
- Review security findings in a structured format.

### Dashboard

- Display scan statistics.
- Show risk distribution.
- Monitor recent scans and alerts.
- Provide an overview of the security analysis environment.

---

## Technologies Used

### Backend

- Python
- FastAPI
- SQLAlchemy
- Pydantic
- REST APIs

### Frontend

- React
- JavaScript
- HTML5
- CSS3
- Vite

### Database

- SQLite

### Development Tools

- Visual Studio Code
- Git
- GitHub
- Postman / Browser API Testing

### Cybersecurity Concepts

- Phishing Detection
- URL Threat Analysis
- Risk Scoring
- Security Alert Management
- Threat Monitoring
- Input Validation
- API Security
- Security Reporting

---

## Project Architecture

```text
                         ┌──────────────────────┐
                         │      React UI        │
                         │ Dashboard / Scanner  │
                         │ Alerts / Reports     │
                         └──────────┬───────────┘
                                    │
                                    │ REST API
                                    ▼
                         ┌──────────────────────┐
                         │     FastAPI API      │
                         │    Python Backend    │
                         └──────────┬───────────┘
                                    │
                    ┌───────────────┼───────────────┐
                    │               │               │
                    ▼               ▼               ▼
             ┌───────────┐  ┌────────────┐  ┌─────────────┐
             │ Detection │  │ Scan &     │  │ Alert       │
             │ Engine    │  │ Database   │  │ Management  │
             └───────────┘  └────────────┘  └─────────────┘
                                    │
                                    ▼
                         ┌──────────────────────┐
                         │       SQLite         │
                         │ Scan Records / Alerts│
                         └──────────────────────┘
