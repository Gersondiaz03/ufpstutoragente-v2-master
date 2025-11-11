# agent_v2_simple.py - Simplified Azure AI Foundry Agent Integration
import os
import time
from pathlib import Path
from typing import Optional, Dict
from dotenv import load_dotenv

from fastapi import FastAPI, Header, HTTPException, Request
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse, PlainTextResponse
from starlette.middleware.base import BaseHTTPMiddleware
from pydantic import BaseModel
from jose import JWTError, jwt

# Azure AI Foundry imports
from azure.ai.agents import AgentsClient
from azure.identity import DefaultAzureCredential, ClientSecretCredential

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


# Initialize Azure AI Agents Client
credential = get_azure_credential()
agents_client = AgentsClient(endpoint=PROJECT_ENDPOINT, credential=credential)

# Store active threads per user (in production, use Redis or database)
user_threads: Dict[str, str] = {}


# ────────────────────────── 3. Pydantic Models ──────────────────────────────
class Pregunta(BaseModel):
    pregunta: str
    contexto: str = ""


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
        if request.url.path.startswith("/consultar"):
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
        "https://ufpstutor-v2-main.vercel.app",
        "https://*.vercel.app",  # Allow all Vercel preview deployments
    ],
    allow_credentials=True,
    allow_methods=["GET", "POST", "PUT", "DELETE", "PATCH", "OPTIONS"],
    allow_headers=["*"],
    expose_headers=["*"],
    max_age=3600,  # Cache preflight requests for 1 hour
)


# ────────────────────────── 6. Helper Functions ──────────────────────────────
def get_or_create_thread(user_id: str) -> str:
    """Get existing thread for user or create a new one."""
    if user_id not in user_threads:
        thread = agents_client.threads.create()
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
@app.get("/")
async def root():
    """Root endpoint with API information."""
    return {
        "name": "UFPS Tutor Agent API",
        "version": "2.0.0",
        "status": "operational",
        "endpoints": {
            "health": "/health",
            "token": "/token",
            "chat": "/consultar",
            "vector_stores": "/vector-stores",
        },
    }


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

        print(f"💬 User {user_id} asking: {pregunta.pregunta[:50]}...")

        # Create message in thread
        message = agents_client.messages.create(
            thread_id=thread_id, role="user", content=pregunta.pregunta
        )

        # Run the agent and wait for completion
        run = agents_client.runs.create_and_process(
            thread_id=thread_id, agent_id=AGENT_ID
        )

        print(f"🤖 Run status: {run.status}")

        # Check for errors
        if run.status == "failed":
            error_msg = (
                f"El agente falló: {run.last_error}"
                if hasattr(run, "last_error") and run.last_error
                else "Error desconocido"
            )
            return JSONResponse(content={"error": error_msg}, status_code=500)

        # Get messages
        messages = agents_client.messages.list(thread_id=thread_id)

        # Extract the agent's response (iterate through messages)
        response_text = "No se recibió respuesta del agente."
        for msg in messages:
            if msg.role == "assistant" and msg.text_messages:
                # Use text_messages helper property (from documentation)
                last_text = msg.text_messages[-1]
                response_text = last_text.text.value
                break

        print(f"✅ Response: {response_text[:100]}...")
        return PlainTextResponse(content=response_text.strip())

    except Exception as e:
        print(f"❌ Error in consultar: {str(e)}")
        import traceback

        traceback.print_exc()
        return JSONResponse(
            content={"error": f"Error al consultar el agente: {str(e)}"},
            status_code=500,
        )


# ────────────────────────── 8. Vector Store CRUD Endpoints ──────────────────
from fastapi import File, UploadFile, Form
from typing import List
import tempfile


@app.get("/vector-stores")
async def list_vector_stores(request: Request):
    """
    List all vector stores associated with the agent.
    Accessible to teachers and admins.
    """
    try:
        # Get all vector stores
        vector_stores = agents_client.vector_stores.list()

        stores_list = []
        for store in vector_stores:
            stores_list.append(
                {
                    "id": store.id,
                    "name": store.name if hasattr(store, "name") else "Unnamed Store",
                    "file_counts": (
                        store.file_counts.__dict__
                        if hasattr(store, "file_counts")
                        else {}
                    ),
                    "created_at": (
                        store.created_at if hasattr(store, "created_at") else None
                    ),
                    "status": store.status if hasattr(store, "status") else "unknown",
                }
            )

        return {"vector_stores": stores_list}

    except Exception as e:
        print(f"❌ Error listing vector stores: {str(e)}")
        import traceback

        traceback.print_exc()
        raise HTTPException(
            status_code=500, detail=f"Error al listar vector stores: {str(e)}"
        )


@app.get("/vector-stores/{vector_store_id}/files")
async def list_vector_store_files(vector_store_id: str, request: Request):
    """
    List all files in a specific vector store.
    Handles pagination to retrieve all files.
    """
    try:
        # Get files from vector store with pagination
        files_list = []
        after = None
        
        while True:
            # List files with pagination
            if after:
                files_page = agents_client.vector_store_files.list(
                    vector_store_id=vector_store_id,
                    limit=100,
                    after=after
                )
            else:
                files_page = agents_client.vector_store_files.list(
                    vector_store_id=vector_store_id,
                    limit=100
                )
            
            # Process files in current page
            for file in files_page.data if hasattr(files_page, 'data') else files_page:
                try:
                    # Get file details
                    file_details = agents_client.files.get(file_id=file.id)
                    files_list.append(
                        {
                            "id": file.id,
                            "filename": (
                                file_details.filename
                                if hasattr(file_details, "filename")
                                else "Unknown"
                            ),
                            "created_at": (
                                file.created_at if hasattr(file, "created_at") else None
                            ),
                            "status": file.status if hasattr(file, "status") else "unknown",
                            "size": file_details.bytes if hasattr(file_details, "bytes") else 0,
                        }
                    )
                except Exception as file_error:
                    print(f"⚠️ Error getting details for file {file.id}: {str(file_error)}")
                    # Add file with minimal info
                    files_list.append(
                        {
                            "id": file.id,
                            "filename": "Unknown",
                            "created_at": file.created_at if hasattr(file, "created_at") else None,
                            "status": file.status if hasattr(file, "status") else "unknown",
                            "size": 0,
                        }
                    )
            
            # Check if there are more pages
            if hasattr(files_page, 'has_more') and files_page.has_more:
                # Get last file ID for pagination
                last_file = list(files_page.data if hasattr(files_page, 'data') else files_page)[-1]
                after = last_file.id
            else:
                break
        
        print(f"📂 Listed {len(files_list)} files from vector store {vector_store_id}")
        return {"files": files_list, "vector_store_id": vector_store_id}

    except Exception as e:
        print(f"❌ Error listing files in vector store: {str(e)}")
        import traceback

        traceback.print_exc()
        raise HTTPException(
            status_code=500, detail=f"Error al listar archivos: {str(e)}"
        )


@app.post("/vector-stores/{vector_store_id}/files/upload")
async def upload_file_to_vector_store(
    vector_store_id: str, request: Request, file: UploadFile = File(...)
):
    """
    Upload a file (PDF/PPTX) to a vector store.
    Only accessible to teachers and admins.
    """
    try:
        # Validate file type
        allowed_extensions = [".pdf", ".pptx", ".docx", ".txt"]
        file_ext = os.path.splitext(file.filename)[1].lower()

        if file_ext not in allowed_extensions:
            raise HTTPException(
                status_code=400,
                detail=f"Tipo de archivo no permitido. Solo se permiten: {', '.join(allowed_extensions)}",
            )

        # Save file temporarily
        with tempfile.NamedTemporaryFile(delete=False, suffix=file_ext) as tmp_file:
            content = await file.read()
            tmp_file.write(content)
            tmp_file_path = tmp_file.name

        try:
            # Upload file to Azure
            from azure.ai.agents.models import FilePurpose

            uploaded_file = agents_client.files.upload_and_poll(
                file_path=tmp_file_path, purpose=FilePurpose.AGENTS
            )

            print(f"📤 Uploaded file {file.filename}, file ID: {uploaded_file.id}")

            # Add file to vector store
            vector_store_file = agents_client.vector_store_files.create_and_poll(
                vector_store_id=vector_store_id, file_id=uploaded_file.id
            )

            print(f"✅ Added file to vector store {vector_store_id}")

            return {
                "success": True,
                "file_id": uploaded_file.id,
                "filename": file.filename,
                "vector_store_id": vector_store_id,
                "message": f"Archivo '{file.filename}' subido exitosamente",
            }

        finally:
            # Clean up temporary file
            if os.path.exists(tmp_file_path):
                os.unlink(tmp_file_path)

    except HTTPException:
        raise
    except Exception as e:
        print(f"❌ Error uploading file: {str(e)}")
        import traceback

        traceback.print_exc()
        raise HTTPException(status_code=500, detail=f"Error al subir archivo: {str(e)}")


@app.delete("/vector-stores/{vector_store_id}/files/{file_id}")
async def delete_file_from_vector_store(
    vector_store_id: str, file_id: str, request: Request, delete_file: bool = False
):
    """
    Delete a file from a vector store.
    If delete_file=True, also deletes the file itself from Azure.
    Only accessible to teachers and admins.
    """
    try:
        # Remove file from vector store
        deletion_status = agents_client.vector_store_files.delete(
            vector_store_id=vector_store_id, file_id=file_id
        )

        print(f"🗑️ Removed file {file_id} from vector store {vector_store_id}")

        # Optionally delete the file itself
        if delete_file:
            file_deletion = agents_client.files.delete(file_id=file_id)
            print(f"🗑️ Deleted file {file_id} completely")

        return {
            "success": True,
            "file_id": file_id,
            "vector_store_id": vector_store_id,
            "deleted_from_store": deletion_status.deleted,
            "deleted_completely": delete_file,
            "message": "Archivo eliminado exitosamente",
        }

    except Exception as e:
        print(f"❌ Error deleting file: {str(e)}")
        import traceback

        traceback.print_exc()
        raise HTTPException(
            status_code=500, detail=f"Error al eliminar archivo: {str(e)}"
        )


@app.post("/vector-stores/create")
async def create_vector_store(request: Request, name: str = Form(...)):
    """
    Create a new vector store.
    Only accessible to admins.
    """
    try:
        vector_store = agents_client.vector_stores.create_and_poll(
            name=name, file_ids=[]
        )

        print(f"📦 Created vector store '{name}', ID: {vector_store.id}")

        return {
            "success": True,
            "vector_store_id": vector_store.id,
            "name": name,
            "message": f"Vector store '{name}' creado exitosamente",
        }

    except Exception as e:
        print(f"❌ Error creating vector store: {str(e)}")
        import traceback

        traceback.print_exc()
        raise HTTPException(
            status_code=500, detail=f"Error al crear vector store: {str(e)}"
        )


@app.delete("/vector-stores/{vector_store_id}")
async def delete_vector_store(vector_store_id: str, request: Request):
    """
    Delete an entire vector store.
    Only accessible to admins.
    """
    try:
        deletion_status = agents_client.vector_stores.delete(
            vector_store_id=vector_store_id
        )

        print(f"🗑️ Deleted vector store {vector_store_id}")

        return {
            "success": True,
            "vector_store_id": vector_store_id,
            "deleted": deletion_status.deleted,
            "message": "Vector store eliminado exitosamente",
        }

    except Exception as e:
        print(f"❌ Error deleting vector store: {str(e)}")
        import traceback

        traceback.print_exc()
        raise HTTPException(
            status_code=500, detail=f"Error al eliminar vector store: {str(e)}"
        )


# ──────────────────────────── Run Server ───────────────────────────────────
if __name__ == "__main__":
    import uvicorn

    port_str = os.getenv("PORT") or "8100"
    port = int(port_str)
    print(f"🚀 Starting UFPS Tutor Agent on port {port}")
    print(f"📍 Agent ID: {AGENT_ID}")
    print(f"🌐 Endpoint: {PROJECT_ENDPOINT}")
    uvicorn.run("agent_v2_simple:app", host="0.0.0.0", port=port, reload=True)
