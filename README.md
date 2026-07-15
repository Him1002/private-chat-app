# ChatApp2

A FastAPI chat application with authentication, friend requests, direct messaging, file upload, and WebSocket support.

## Requirements

- Python 3.11
- Virtual environment
- Dependencies are listed in `requirements.txt`

## Setup

1. Open a terminal in the project root (`d:\ChatApp2`).
2. Activate the existing virtual environment:
   - PowerShell: `d:\ChatApp2\chatapp\Scripts\Activate.ps1`
   - Command Prompt: `d:\ChatApp2\chatapp\Scripts\activate.bat`
3. Install dependencies if needed:
   ```powershell
   python -m pip install -r requirements.txt
   ```

## Run

Start the server with Uvicorn:

```powershell
python -m uvicorn main:app --reload --host 127.0.0.1 --port 8000
```

Then open the frontend at:

- `http://127.0.0.1:8000/`

## Project files

- `main.py` - FastAPI application, routes, and WebSocket chat logic
- `database.py` - SQLAlchemy database setup and session management
- `models.py` - User, Friend, and Message models
- `requirements.txt` - pinned Python dependencies
- `static/index1.html` - frontend entrypoint

## Notes

- The app uses SQLite database `chat.db` in the project root.
- Uploaded files are served from the `uploads/` folder.
- Change `SECRET_KEY` in `main.py` before deploying to production.
