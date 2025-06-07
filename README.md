## Setup

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
createdb incident_response
pg_ctl -D ./postgres -l logfile start
```
5. Set environment variables (optional):
```bash
export DATABASE_URL=postgresql://yourusername:yourpassword@localhost:5432/incident_response
export JWT_SECRET_KEY=your-jwt-secret
export SESSION_SECRET=your-session-secret
```

## Usage

### On Replit
1. Click the "Run" button in Replit to start the application

### Local Development
1. Start the PostgreSQL server if not running:
```bash
pg_ctl -D ./postgres -l logfile start
```
2. Run the Flask application:
```bash
python main.py
```
Or with Gunicorn:
```bash
gunicorn --bind 0.0.0.0:5000 --reload main:app
```