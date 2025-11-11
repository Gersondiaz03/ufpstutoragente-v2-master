# UFPSTutor Agent - Database Teaching Assistant

This is the intelligent agent component of UFPSTutor, specialized in providing academic support for Database subjects at Universidad Francisco de Paula Santander.

## Features

- **RAG-based Knowledge Base**: Uses PDF documents about databases to provide accurate theoretical answers
- **Azure OpenAI Integration**: Powered by Azure OpenAI for reliable and high-quality responses
- **Dual Function Support**:
  - Theoretical questions about database concepts
  - Practical exercises involving SQL, table design, and data modeling
- **JWT Authentication**: Secure endpoint access
- **Rate Limiting**: Protection against abuse

## Setup

### 1. Environment Variables

Copy `.env.example` to `.env` and configure:

```bash
cp .env.example .env
```

Required variables:

- `AZURE_OPENAI_ENDPOINT`: Your Azure OpenAI resource endpoint
- `AZURE_OPENAI_API_KEY`: Your Azure OpenAI API key
- `AZURE_OPENAI_DEPLOYMENT`: Your chat completion deployment name
- `JWT_SECRET`: Secret key for JWT token generation

### 2. Install Dependencies

```bash
pip install -r requirements.txt
```

### 3. Add PDF Knowledge Base

Ensure these PDF files are in the project root:

- `FundamentosDeSistemasDeBasesDeDatos.pdf`
- `LibroBasesDeDatos.pdf`
- `SQLNotesForProfessionals.pdf`
- `databaseengineeringtheory.pdf`

### 4. Run the Agent

```bash
python agent.py
```

The agent will start on port 8100 by default.

## API Endpoints

### Authentication

**POST /token**

- Generates JWT token for authenticated requests
- Returns: `{"access_token": "...", "token_type": "bearer"}`

### Query Agent

**POST /consultar**

- Headers: `Authorization: Bearer <token>`
- Body: `{"pregunta": "Your question", "contexto": "Optional context"}`
- Returns: Plain text response

### Health Check

**GET /health**

- Returns: `{"status": "ok"}`

## How It Works

1. **Question Classification**: The agent automatically determines if a question is theoretical or practical
2. **Knowledge Retrieval**: For theoretical questions, it searches the PDF knowledge base
3. **Response Generation**: Uses Azure OpenAI to generate pedagogical, clear responses
4. **Practical Solutions**: For exercises, provides step-by-step solutions with SQL code when needed

## Integration

This agent is designed to work with the UFPSTutor frontend and backend:

- Frontend: React/Next.js application
- Backend: FastAPI application with user management
- Agent: This service for intelligent responses

## CORS Configuration

Configured to accept requests from:

- `http://localhost:3000` (development)
- `http://127.0.0.1:3000` (development)
- `http://localhost:3001` (alternative development)
- `https://ufpstutor.vercel.app` (production)
