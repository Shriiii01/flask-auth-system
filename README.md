Simple FastAPI Authentication System

A clean and simple authentication system built with FastAPI. Features basic signup, login, logout, and token refresh functionality.

Key Features

- Simple Signup & Login: Easy user registration and authentication
- JWT Tokens: Secure access and refresh tokens
- Supabase Database: Uses Supabase PostgreSQL for data storage
- Rate Limiting: Protection against abuse using Redis
- API Documentation: Built-in Swagger UI documentation

Tech Stack

- Framework: FastAPI
- Database: Supabase (PostgreSQL)
- Authentication: JWT via python-jose
- Rate Limiting: slowapi with Redis
- Deployment: Docker with Uvicorn

Getting Started

Docker (Recommended)

git clone https://github.com/Shriiii01/flask-auth-system.git
cd flask-auth-system
cp .env.example .env  # Update your environment variables
docker-compose up --build

Manual (Local Development)

git clone https://github.com/Shriiii01/flask-auth-system.git
cd flask-auth-system
python3 -m venv venv
source venv/bin/activate
pip install -r requirements.txt
cp .env.example .env  # Update environment variables accordingly
flask db upgrade
flask run

Access Swagger documentation at:
http://localhost:5001/docs

API Documentation

The API is fully documented with Swagger UI, including interactive testing, authentication via JWT tokens, and clear API contracts.
Additionally, you can directly import our Postman Collection for immediate testing and integration.

Project Structure

The architecture follows a logical and modular design:

flask_auth/
├── routes/
│   ├── auth.py
│   ├── main.py
│   └── admin_routes.py
├── models/
│   └── user.py, role.py, logs.py
├── utils/
│   └── decorators, logger, helpers
├── extensions.py
├── config.py
├── Dockerfile
├── docker-compose.yml
├── run.py

Security and Best Practices

This project carefully implements numerous security best practices:

Secure JWT token handling with appropriate expiry.
Password hashing using bcrypt.
Strict rate limiting to avoid brute-force attacks.
Proper database management with migrations.
Secure OAuth authentication.
Sensitive data isolated in environment variables.
Possible Extensions

Future improvements and expansions could include:

Additional OAuth providers (Google, LinkedIn).
Two-Factor Authentication (2FA) via authenticator apps.
Frontend integration with React or Vue.js for a complete user interface.
Analytics dashboards for administrators to monitor user activity.
Advanced logging and alerting for security monitoring.
Target Audience

This system is intended for developers, teams, startups, and companies looking for:

A production-grade authentication system without vendor lock-in.
Highly customizable and secure authentication flows.
Reliable backend services for sensitive user operations.
Final Thoughts

This project was built not as a classroom exercise, but as a demonstration of genuine backend engineering capability. The intention was to create something meaningful, maintainable, and production-ready. While the internet is flooded with tutorials and trivial demos, authentic projects like this serve as a clear indicator of the practical skills and commitment to best practices required in serious backend development.

If you're evaluating my engineering capabilities—whether for hiring, collaboration, or building the next big thing—this project speaks louder than a resume. It shows not just familiarity with technologies, but the understanding and insight needed to build reliable, scalable, and secure software.

Email: shrijambhale8@gmail.com
