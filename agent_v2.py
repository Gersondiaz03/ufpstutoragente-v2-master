# agent_v2.py - Azure AI Foundry Agent Integration with Vector Store CRUD
import os
import time
from pathlib import Path
from typing import Optional, Dict, List, Any
from dotenv import load_dotenv

from fastapi import FastAPI, Header, HTTPException, Request, UploadFile, File, Form
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse, PlainTextResponse, StreamingResponse
from starlette.middleware.base import BaseHTTPMiddleware
from pydantic import BaseModel
from jose import JWTError, jwt

# Azure AI Foundry imports
from azure.ai.projects import AIProjectClient
from azure.ai.agents.models import ListSortOrder, MessageRole
from azure.identity import DefaultAzureCredential, ClientSecretCredential
from azure.core.credentials import AzureKeyCredential

# For file handling
import io
import mimetypes

# ────────────────────────── 1. ENV y CREDENCIALES ──────────────────────────
load_dotenv(dotenv_path=Path(__file__).with_name(".env"))

JWT_SECRET = os.getenv("JWT_SECRET") or ""
JWT_ALGORITHM = os.getenv("JWT_ALGORITHM", "HS256")

# Azure AI Foundry configuration
PROJECT_ENDPOINT = os.getenv("AZURE_EXISTING_AIPROJECT_ENDPOINT") or ""
AGENT_ID = os.getenv("AZURE_EXISTING_AGENT_ID") or ""

# Service Principal credentials for production (no az login required)
AZURE_CLIENT_ID = os.getenv("AZURE_CLIENT_ID")
AZURE_TENANT_ID = os.getenv("AZURE_TENANT_ID")
AZURE_CLIENT_SECRET = os.getenv("AZURE_CLIENT_SECRET")

if not PROJECT_ENDPOINT or not AGENT_ID:
    raise RuntimeError(
        "Missing required environment variables: AZURE_EXISTING_AIPROJECT_ENDPOINT or AZURE_EXISTING_AGENT_ID"
    )


# ────────────────────────── 2. Azure Authentication Setup ──────────────────
def get_azure_credential():
    """
    Returns appropriate Azure credential based on environment.
    - Production (Docker/Render): Uses ClientSecretCredential with service principal
    - Development: Uses DefaultAzureCredential (falls back to az login if available)
    """
    if AZURE_CLIENT_ID and AZURE_TENANT_ID and AZURE_CLIENT_SECRET:
        print("🔐 Using ClientSecretCredential (Service Principal) for authentication")
        return ClientSecretCredential(
            tenant_id=AZURE_TENANT_ID,
            client_id=AZURE_CLIENT_ID,
            client_secret=AZURE_CLIENT_SECRET,
        )
    else:
        print("🔐 Using DefaultAzureCredential (may require az login in local dev)")
        return DefaultAzureCredential(exclude_interactive_browser_credential=True)


# Initialize Azure AI Project Client
credential = get_azure_credential()
project_client = AIProjectClient(endpoint=PROJECT_ENDPOINT, credential=credential)

# Get the agents client directly from project_client.agents
# Note: The Python SDK uses project_client.agents, not get_persistent_agents_client()

# Store active threads per user (in production, use Redis or database)
user_threads: Dict[str, str] = {}


# ────────────────────────── 3. Pydantic Models ──────────────────────────────
class Pregunta(BaseModel):
    pregunta: str
    contexto: str = ""


class VectorStoreResponse(BaseModel):
    id: str
    name: str
    file_counts: Dict[str, int]
    status: str
    created_at: int


# ────────────────────────── 4. Security Middleware ──────────────────────────
request_timestamps = {}


class SecurityMiddleware(BaseHTTPMiddleware):
    async def dispatch(self, request: Request, call_next):
        # Rate-limit by IP
        ip = request.client.host if request.client else "unknown"
        now = time.time()
        request_timestamps.setdefault(ip, [])
        request_timestamps[ip] = [t for t in request_timestamps[ip] if now - t < 60]

        if len(request_timestamps[ip]) >= 30:  # Increased limit for chat usage
            return JSONResponse(
                status_code=429,
                content={"error": "Demasiadas solicitudes. Intente más tarde."},
            )

        request_timestamps[ip].append(now)

        # Protected endpoints require JWT
        protected_paths = ["/consultar", "/vector-stores", "/vector-stores/"]
        if any(request.url.path.startswith(path) for path in protected_paths):
            auth = request.headers.get("Authorization", "")
            if not auth.startswith("Bearer "):
                return JSONResponse(
                    status_code=401, content={"error": "Token JWT faltante o inválido."}
                )

            token_jwt = auth.replace("Bearer ", "")
            try:
                jwt.decode(token_jwt, JWT_SECRET, algorithms=[JWT_ALGORITHM])
            except JWTError:
                return JSONResponse(
                    status_code=403, content={"error": "Token JWT inválido o expirado."}
                )

        return await call_next(request)


# ────────────────────────── 5. FastAPI Application ──────────────────────────
app = FastAPI(title="UFPS Tutor Agent API", version="2.0.0")
app.add_middleware(SecurityMiddleware)

app.add_middleware(
    CORSMiddleware,
    allow_origins=[
        "http://localhost:3000",
        "http://127.0.0.1:3000",
        "http://localhost:3001",
        "https://ufpstutor.vercel.app",
        "https://ufpstutorv2.vercel.app",
    ],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)


# ────────────────────────── 6. Helper Functions ──────────────────────────────
def get_or_create_thread(user_id: str) -> str:
    """Get existing thread for user or create a new one."""
    if user_id not in user_threads:
        thread = project_client.agents.threads.create()
        user_threads[user_id] = thread.id
        print(f"📝 Created new thread {thread.id} for user {user_id}")
    return user_threads[user_id]


def extract_user_id(request: Request, x_user_id: Optional[str] = None) -> str:
    """Extract user ID from JWT or header."""
    uid = "anonymous"

    # Try JWT first
    auth = request.headers.get("Authorization", "")
    if auth.startswith("Bearer "):
        token_jwt = auth.replace("Bearer ", "")
        try:
            if JWT_SECRET:
                payload = jwt.decode(token_jwt, JWT_SECRET, algorithms=[JWT_ALGORITHM])
                sub = payload.get("sub")
                if isinstance(sub, (int, float)):
                    uid = str(int(sub))
                elif isinstance(sub, str):
                    uid = sub
        except JWTError:
            pass

    # Fallback to header
    if uid == "anonymous" and x_user_id:
        uid = x_user_id

    return uid


# ────────────────────────── 7. Endpoints ─────────────────────────────────────
@app.get("/health")
async def health():
    """Health check endpoint."""
    return {
        "status": "ok",
        "agent_id": AGENT_ID,
        "endpoint": PROJECT_ENDPOINT,
        "auth_method": "service_principal" if AZURE_CLIENT_ID else "default",
    }


@app.post("/token")
async def generar_token():
    """Generate JWT token for API access."""
    if not JWT_SECRET:
        raise HTTPException(status_code=500, detail="JWT_SECRET no configurado")

    token = jwt.encode(
        {"sub": "usuario_autenticado"}, JWT_SECRET, algorithm=JWT_ALGORITHM
    )
    return {"access_token": token, "token_type": "bearer"}


@app.post("/consultar")
async def endpoint_consultar(
    pregunta: Pregunta,
    request: Request,
    x_user_id: Optional[str] = Header(default=None, alias="X-User-Id"),
):
    """
    Main chat endpoint using Azure AI Foundry Agent.
    Handles user questions with context and maintains conversation threads.
    """
    try:
        user_id = extract_user_id(request, x_user_id)
        thread_id = get_or_create_thread(user_id)

        # Create message in thread
        message = project_client.agents.messages.create(
            thread_id=thread_id, role=MessageRole.USER, content=pregunta.pregunta
        )

        # Run the agent
        run = project_client.agents.runs.create_and_process(
            thread_id=thread_id, agent_id=AGENT_ID
        )

        # Check for errors
        if run.status == "failed":
            error_msg = (
                f"El agente falló: {run.last_error}"
                if run.last_error
                else "Error desconocido"
            )
            return JSONResponse(content={"error": error_msg}, status_code=500)

        # Get messages (most recent first)
        messages = project_client.agents.messages.list(
            thread_id=thread_id, order=ListSortOrder.DESCENDING, limit=1
        )

        # Extract the agent's response
        response_text = "No se recibió respuesta del agente."
        if messages.data and len(messages.data) > 0:
            last_message = messages.data[0]
            if (
                last_message.role == MessageRole.ASSISTANT
                and last_message.text_messages
            ):
                response_text = last_message.text_messages[-1].text.value

        return PlainTextResponse(content=response_text.strip())

    except Exception as e:
        print(f"❌ Error in consultar: {str(e)}")
        return JSONResponse(
            content={"error": f"Error al consultar el agente: {str(e)}"},
            status_code=500,
        )


@app.get("/vector-stores")
async def list_vector_stores():
    """
    List all vector stores in the project.
    For teachers to view available knowledge bases.
    """
    try:
        # Get the agent details to find its vector store
        agent = project_client.agents.get_agent(AGENT_ID)

        vector_stores = []

        # Check if agent has file search tool configured
        if agent.tools:
            for tool in agent.tools:
                if hasattr(tool, "vector_store_ids"):
                    for vs_id in tool.vector_store_ids:
                        try:
                            vs = project_client.agents.vector_stores.get_vector_store(
                                vs_id
                            )
                            vector_stores.append(
                                {
                                    "id": vs.id,
                                    "name": vs.name or "Sin nombre",
                                    "file_counts": {
                                        "total": (
                                            vs.file_counts.total
                                            if vs.file_counts
                                            else 0
                                        ),
                                        "completed": (
                                            vs.file_counts.completed
                                            if vs.file_counts
                                            else 0
                                        ),
                                        "in_progress": (
                                            vs.file_counts.in_progress
                                            if vs.file_counts
                                            else 0
                                        ),
                                        "failed": (
                                            vs.file_counts.failed
                                            if vs.file_counts
                                            else 0
                                        ),
                                    },
                                    "status": vs.status,
                                    "created_at": vs.created_at,
                                }
                            )
                        except Exception as e:
                            print(f"Error getting vector store {vs_id}: {e}")

        return JSONResponse(content={"vector_stores": vector_stores})

    except Exception as e:
        print(f"❌ Error listing vector stores: {str(e)}")
        return JSONResponse(
            content={"error": f"Error al listar vector stores: {str(e)}"},
            status_code=500,
        )


@app.get("/vector-stores/{vector_store_id}/files")
async def list_vector_store_files(vector_store_id: str):
    """
    List all files in a specific vector store.
    """
    try:
        files = agents_client.vector_stores.files.list(vector_store_id=vector_store_id)

        file_list = []
        for file in files.data:
            file_list.append(
                {
                    "id": file.id,
                    "vector_store_id": file.vector_store_id,
                    "status": file.status,
                    "created_at": file.created_at,
                }
            )

        return JSONResponse(content={"files": file_list})

    except Exception as e:
        print(f"❌ Error listing files: {str(e)}")
        return JSONResponse(
            content={"error": f"Error al listar archivos: {str(e)}"}, status_code=500
        )


@app.post("/vector-stores/{vector_store_id}/files")
async def upload_file_to_vector_store(
    vector_store_id: str, file: UploadFile = File(...)
):
    """
    Upload a file (PDF or PPTX) to a vector store.
    For teachers to add knowledge base documents.
    """
    try:
        # Validate file type
        allowed_types = [
            "application/pdf",
            "application/vnd.ms-powerpoint",
            "application/vnd.openxmlformats-officedocument.presentationml.presentation",
        ]

        content_type = file.content_type or mimetypes.guess_type(file.filename)[0]
        if content_type not in allowed_types:
            raise HTTPException(
                status_code=400, detail="Solo se permiten archivos PDF y PPTX"
            )

        # Read file content
        file_content = await file.read()
        file_stream = io.BytesIO(file_content)

        # Upload file to Azure
        uploaded_file = project_client.agents.upload_file_and_poll(
            file_stream, purpose="assistants", file_name=file.filename
        )

        # Add file to vector store
        vs_file = project_client.agents.vector_stores.create_vector_store_file_and_poll(
            vector_store_id=vector_store_id, file_id=uploaded_file.id
        )

        return JSONResponse(
            content={
                "message": "Archivo subido exitosamente",
                "file_id": vs_file.id,
                "status": vs_file.status,
            }
        )

    except Exception as e:
        print(f"❌ Error uploading file: {str(e)}")
        return JSONResponse(
            content={"error": f"Error al subir archivo: {str(e)}"}, status_code=500
        )


@app.delete("/vector-stores/{vector_store_id}/files/{file_id}")
async def delete_file_from_vector_store(vector_store_id: str, file_id: str):
    """
    Delete a file from a vector store.
    For teachers to remove outdated documents.
    """
    try:
        # Delete from vector store
        project_client.agents.vector_stores.delete_vector_store_file(
            vector_store_id=vector_store_id, file_id=file_id
        )

        # Also delete the file from the project
        try:
            project_client.agents.delete_file(file_id)
        except:
            pass  # File might be used elsewhere

        return JSONResponse(content={"message": "Archivo eliminado exitosamente"})

    except Exception as e:
        print(f"❌ Error deleting file: {str(e)}")
        return JSONResponse(
            content={"error": f"Error al eliminar archivo: {str(e)}"}, status_code=500
        )


@app.post("/vector-stores/{vector_store_id}/clear")
async def clear_vector_store(vector_store_id: str):
    """
    Clear all files from a vector store.
    """
    try:
        files = project_client.agents.vector_stores.list_vector_store_files(
            vector_store_id=vector_store_id
        )

        deleted_count = 0
        for file in files.data:
            try:
                project_client.agents.vector_stores.delete_vector_store_file(
                    vector_store_id=vector_store_id, file_id=file.id
                )
                deleted_count += 1
            except Exception as e:
                print(f"Error deleting file {file.id}: {e}")

        return JSONResponse(
            content={
                "message": f"Se eliminaron {deleted_count} archivos",
                "deleted_count": deleted_count,
            }
        )

    except Exception as e:
        print(f"❌ Error clearing vector store: {str(e)}")
        return JSONResponse(
            content={"error": f"Error al limpiar vector store: {str(e)}"},
            status_code=500,
        )


# ──────────────────────────── Run Server ───────────────────────────────────
if __name__ == "__main__":
    import uvicorn

    port_str = os.getenv("PORT") or "8100"
    port = int(port_str)
    uvicorn.run("agent_v2:app", host="0.0.0.0", port=port, reload=True)
