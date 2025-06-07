## Setup

### Virtual Environment Setup
1. Create a virtual environment:
```powershell
python -m venv venv
```
2. Activate the virtual environment:
- Windows (PowerShell):
```powershell
.\venv\Scripts\Activate.ps1
```
- Windows (Command Prompt):
```cmd
.\venv\Scripts\activate.bat
```
- Linux/macOS:
```bash
source venv/bin/activate
```

### Replit Setup
1. Clone the repository in Replit
2. The required Python packages are automatically installed via requirements.txt

### Local Development Setup
1. Clone the repository to your local machine
2. Install PostgreSQL on your system if not already installed
3. Install Python dependencies:
```bash
pip install -r requirements.txt
```
4. Initialize PostgreSQL database:
```bash
initdb -D ./postgres
pg_ctl -D ./postgres -l logfile start
createdb incident_response
```
5. Set environment variables (optional):
```powershell
# Set environment variables (Windows PowerShell example):
$env:DATABASE_URL = "postgresql://yourusername:yourpassword@localhost:5432/incident_response"
# (Optional) If your app uses JWT/session secrets:
# $env:JWT_SECRET_KEY = "your-jwt-secret"
# $env:SESSION_SECRET = "your-session-secret"
```

### Database User & Permissions
1. Make sure your PostgreSQL server is running. If you installed PostgreSQL as a Windows service, it may already be running. Otherwise, start it with:
   ```powershell
   pg_ctl -D ./postgres -l logfile start
   ```
2. Create a database user and set a password (replace `yourusername`/`yourpassword`):
   ```powershell
   psql -U harsh -d postgres
   ```
   Then in the psql prompt:
   ```sql
   CREATE USER yourusername WITH PASSWORD 'yourpassword';
   ALTER USER yourusername CREATEDB;
   ALTER DATABASE incident_response OWNER TO yourusername;
   \q
   ```

### Troubleshooting
- If you get connection errors, make sure the PostgreSQL server is running and your credentials are correct.
- If you see errors about missing tables (e.g., `relation "users" does not exist`), just run your Flask app with `python main.py`—it will auto-create the tables if they don't exist.
- If you see `Error: No such command 'db'` when running `flask db upgrade`, your project does not use Flask-Migrate. Table creation is handled automatically by the app.

## Usage
gunicorn --bind 0.0.0.0:5000 --reload main:app

### On Replit
1. Click the "Run" button in Replit to start the application.

### Local Development
1. Start the PostgreSQL server if not running:
   ```powershell
   pg_ctl -D ./postgres -l logfile start
   ```
2. Run the Flask application (this will also auto-create tables if needed):
   ```powershell
   python main.py
   ```
   Or with Gunicorn (if installed):
   ```powershell
   gunicorn --bind 0.0.0.0:5000 --reload main:app
   ```

### How Table Creation Works
- When you run `python main.py`, the app will automatically create any missing tables in your database (using SQLAlchemy's `db.create_all()` or similar). You do **not** need to run `flask db upgrade` unless you add Flask-Migrate to your project.

### Checking Your Tables
To verify your tables exist, you can use psql:
```powershell
psql -U yourusername -d incident_response
\dt
```
You should see tables like `users`, `incidents`, etc.