# LinkGuard 

LinkGuard is a web application that analyzes URL structures and identifies potential risk indicators using rule-based scoring.

The project combines a FastAPI backend with a React frontend to present URL analysis results in a simple interface.

## Features

- Analyze URL structure and extract information such as scheme, hostname, and path.
- Identify potential risk indicators, including IP addresses used as hostnames and URLs that do not use HTTPS.
- Calculate a risk score based on predefined rules.
- Display analysis results and explanations through a web interface.
- Run automated tests for the URL analyzer.

## Tech Stack

Backend

- Python
- FastAPI
- Pydantic
- Pytest

Frontend

- React
- Vite
- JavaScript
- CSS

## Project Structure

```text
LinkGuard/
├── app/
│   ├── __init__.py
│   ├── main.py
│   └── url_analyzer.py
├── frontend/
│   ├── public/
│   └── src/
├── tests/
├── requirements.txt
└── README.md
```

## Run Locally

### 1. Clone the repository

```bash
git clone https://github.com/zahiraputri28/LinkGuard.git
cd LinkGuard
```

### 2. Set up the backend

Create and activate a Python virtual environment, then install the dependencies.

```bash
python -m venv .venv
```

On Windows PowerShell:

```powershell
.\.venv\Scripts\Activate.ps1
pip install -r requirements.txt
```

Start the API:

```bash
python -m uvicorn app.main:app --reload
```

Open the API documentation at http://127.0.0.1:8000/docs.

### 3. Set up the frontend

Open a second terminal:

```powershell
cd frontend
npm install
```

Create a local `.env.local` file in the `frontend` folder with the following configuration:

```text
VITE_API_URL=http://127.0.0.1:8000
```

Start the frontend:

```bash
npm run dev
```

Open the local address displayed in the terminal, usually http://localhost:5173.

## Testing

From the project root, activate the virtual environment and run:

```bash
python -m pytest
```

## Important Disclaimer

LinkGuard uses rule-based URL analysis. Its risk score indicates structural warning signs and does not prove that a URL is malicious or safe. Do not rely on the score alone when deciding whether to visit a URL.

## Project Status

This project is intended for learning and portfolio demonstration. The application can be run locally without deploying it as a public website.
