# agent.py
import os
import time

from dotenv import load_dotenv
from pathlib import Path
from fastapi import FastAPI, Header, HTTPException, Request
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse, PlainTextResponse
from jose import JWTError, jwt
from pydantic import BaseModel
from starlette.middleware.base import BaseHTTPMiddleware

# OpenAI (Azure) and Agents SDK
# Keep AzureOpenAI client for compatibility if needed
# Removed Agents SDK usage to avoid non-Azure tracing and simplify flow

# RAG stack
from langchain_core.documents import Document
from langchain_text_splitters import RecursiveCharacterTextSplitter
from langchain_chroma import Chroma
from typing import Optional
import requests

try:
    from langchain_openai import AzureOpenAIEmbeddings  # type: ignore
except Exception:
    AzureOpenAIEmbeddings = None  # type: ignore
from langchain_nomic.embeddings import NomicEmbeddings
import fitz  # PyMuPDF

# ────────────────────────── 1. ENV y CREDENCIALES ──────────────────────────
load_dotenv(dotenv_path=Path(__file__).with_name(".env"))
# Ensure OpenAI platform client does not attempt tracing with Azure key
for _var in ("OPENAI_API_KEY", "OPENAI_ORG_ID", "OPENAI_PROJECT", "OPENAI_BASE_URL"):
    if os.environ.get(_var):
        os.environ.pop(_var, None)
JWT_SECRET = os.getenv("JWT_SECRET") or ""
JWT_ALGORITHM = os.getenv("JWT_ALGORITHM", "HS256")

# ─────────────────── 2. LLM (Azure OpenAI) y Embeddings (Nomic) ────────────
AZURE_ENDPOINT = os.getenv("AZURE_OPENAI_ENDPOINT") or ""
AZURE_API_KEY = os.getenv("AZURE_OPENAI_API_KEY") or ""
# Prefer stable GA version by default; allow env override
AZURE_API_VERSION = os.getenv("AZURE_OPENAI_API_VERSION", "2024-10-21")

if not AZURE_ENDPOINT or not AZURE_API_KEY:
    raise RuntimeError(
        "Faltan variables de entorno de Azure OpenAI (endpoint o api key)"
    )

AZURE_DEPLOYMENT = os.getenv("AZURE_OPENAI_DEPLOYMENT") or ""
# Only include temperature if explicitly provided; some models only support default (1)
_TEMP_RAW = os.getenv("AZURE_TEMPERATURE")
TEMPERATURE: Optional[float] = None
if _TEMP_RAW is not None and _TEMP_RAW.strip() != "":
    try:
        TEMPERATURE = float(_TEMP_RAW)
    except Exception:
        TEMPERATURE = None

# Prefer Azure OpenAI embeddings if configured; fallback to Nomic
AZURE_EMBEDDINGS_DEPLOYMENT = os.getenv("AZURE_OPENAI_EMBEDDINGS_DEPLOYMENT") or ""
embeddings = None
if AzureOpenAIEmbeddings and AZURE_EMBEDDINGS_DEPLOYMENT:
    try:
        embeddings = AzureOpenAIEmbeddings(
            azure_endpoint=AZURE_ENDPOINT,
            api_key=AZURE_API_KEY,
            openai_api_version=AZURE_API_VERSION,
            azure_deployment=AZURE_EMBEDDINGS_DEPLOYMENT,
        )
    except Exception:
        embeddings = None
if embeddings is None:
    embeddings = NomicEmbeddings(model="nomic-embed-text-v1.5")


def azure_chat_complete(prompt: str) -> str:
    if not AZURE_DEPLOYMENT:
        raise RuntimeError("Falta AZURE_OPENAI_DEPLOYMENT en variables de entorno.")

    original_endpoint = AZURE_ENDPOINT.strip().rstrip("/")

    # Generate normalized endpoint host: {resource}.openai.azure.com
    normalized_endpoint = original_endpoint
    try:
        if ".cognitiveservices.azure.com" in original_endpoint:
            from urllib.parse import urlparse

            parsed = urlparse(original_endpoint)
            resource = (parsed.hostname or "").split(".")[0]
            if resource:
                normalized_endpoint = f"{parsed.scheme}://{resource}.openai.azure.com"
    except Exception:
        normalized_endpoint = original_endpoint

    endpoints_to_try = [e for e in {original_endpoint, normalized_endpoint} if e]

    headers = {"api-key": AZURE_API_KEY, "Content-Type": "application/json"}

    def _do_request(endpoint: str, api_version: str, include_temperature: bool = True):
        url = f"{endpoint}/openai/deployments/{AZURE_DEPLOYMENT}/chat/completions"
        params = {"api-version": api_version}
        body: dict[str, object] = {
            "messages": [
                {
                    "role": "system",
                    "content": (
                        "Eres un asistente virtual académico de la UNIVERSIDAD FRANCISCO DE PAULA SANTANDER, "
                        "especializado en Bases de Datos. Brindas apoyo teórico y práctico a estudiantes de ingeniería "
                        "con claridad pedagógica y ejemplos concretos cuando es necesario."
                    ),
                },
                {"role": "user", "content": prompt},
            ],
        }
        if include_temperature and TEMPERATURE is not None:
            body["temperature"] = TEMPERATURE
        return requests.post(url, params=params, headers=headers, json=body, timeout=60)

    errors = []
    for ep in endpoints_to_try:
        # Try configured API version first
        resp = _do_request(ep, AZURE_API_VERSION)
        if resp.status_code == 400 and AZURE_API_VERSION != "2024-10-21":
            # Retry once with stable GA version
            resp = _do_request(ep, "2024-10-21")

        # If temperature is not supported by this model, retry once without sending it
        if resp.status_code == 400:
            try:
                err_json = resp.json()
                param = (err_json.get("error") or {}).get("param") or (
                    err_json.get("innererror") or {}
                ).get("param")
            except Exception:
                param = None
            if param == "temperature":
                resp = _do_request(ep, AZURE_API_VERSION, include_temperature=False)
                if resp.status_code == 400 and AZURE_API_VERSION != "2024-10-21":
                    resp = _do_request(ep, "2024-10-21", include_temperature=False)

        if resp.ok:
            data = resp.json()
            choices = data.get("choices") or []
            if not choices:
                return ""
            msg = choices[0].get("message") or {}
            return (msg.get("content") or "").strip()

        try:
            err = resp.json()
        except Exception:
            err = {"text": resp.text}
        errors.append({"endpoint": ep, "status": resp.status_code, "error": err})

    raise HTTPException(status_code=500, detail={"azure_errors": errors})


# ───────────────────── 3. PDFs → VectorStore (Chroma) ──────────────────────
pdf_paths = [
    r"FundamentosDeSistemasDeBasesDeDatos.pdf",
    r"LibroBasesDeDatos.pdf",
    r"SQLNotesForProfessionals.pdf",
    r"databaseengineeringtheory.pdf",
]


def extract_text_from_pdf(path: str) -> str:
    doc = fitz.open(path)
    text = ""
    for page in doc:
        text += page.get_text()
    return text


raw_text = "\n".join(extract_text_from_pdf(p) for p in pdf_paths)

text_splitter = RecursiveCharacterTextSplitter(
    chunk_size=1000,
    chunk_overlap=200,
    length_function=len,
)
documents = [
    Document(page_content=chunk) for chunk in text_splitter.split_text(raw_text)
]
vectorstore = Chroma.from_documents(documents, embeddings)
retriever = vectorstore.as_retriever()


"""
4. Herramientas (function_tool) para el agente usando OpenAI Agents SDK.
Implementa la misma lógica RAG: recuperar y adaptar la respuesta con el LLM (Azure OpenAI).
"""


def _adaptacion_prompt_teorico(respuesta_original: str, contexto: str) -> str:
    return f"""
Eres un asistente virtual académico de la UNIVERSIDAD FRANCISCO DE PAULA SANTANDER, especializado en Bases de Datos.

Has recibido una respuesta basada en el conocimiento teórico validado. Tu tarea es mejorar la claridad, precisión y estilo pedagógico de esa respuesta, manteniendo la fidelidad al contenido original.

- Explica los conceptos con ejemplos si es necesario.
- Usa un lenguaje formal pero accesible.
- No repitas la pregunta.
- Responde en Español correctamente.
- Si es apropiado, incluye ejemplos prácticos o casos de uso.

### Conocimiento recuperado:
{respuesta_original}

### Contexto adicional:
{contexto}

Redacta la respuesta final clara y pedagógica:
"""


def _adaptacion_prompt_practico(enunciado: str, contexto: str) -> str:
    return f"""
Eres un asistente virtual académico de la UNIVERSIDAD FRANCISCO DE PAULA SANTANDER, especializado en Bases de Datos y desarrollo SQL.

Has recibido un ejercicio práctico que requiere una solución técnica completa, además de una explicación clara y pedagógica de cómo se resolvió.

Tu tarea es resolver el ejercicio como lo haría un estudiante avanzado o un profesor, proporcionando:
- Análisis del problema
- Solución paso a paso
- Código SQL cuando sea necesario
- Explicación de la lógica utilizada

### Enunciado del ejercicio:
{enunciado}

### Contexto adicional:
{contexto}

Proporciona la solución completa y explicada:
"""


def consultar_conocimiento(pregunta: str, contexto: str = "") -> str:
    """Consulta el flujo de análisis de bases de datos (RAG) y adapta la respuesta al contexto."""
    docs = retriever.invoke(pregunta)
    doc_text = (
        "\n\n".join(d.page_content for d in docs[:2])
        or "No se encontró información relevante en la base de conocimiento."
    )

    prompt = _adaptacion_prompt_teorico(doc_text.strip(), contexto)
    return azure_chat_complete(prompt)


def resolver_ejercicios(enunciado: str, contexto: str = "") -> str:
    """Resuelve ejercicios prácticos de bases de datos con explicaciones detalladas."""
    prompt = _adaptacion_prompt_practico(enunciado, contexto)
    return azure_chat_complete(prompt)


INSTRUCTIONS = """
    Eres un asistente virtual académico de la UNIVERSIDAD FRANCISCO DE PAULA SANTANDER, especializado en Bases de Datos.
    Objetivo: brindar apoyo teórico y práctico a estudiantes de ingeniería en temas de bases de datos.
    - Adapta las explicaciones al nivel del estudiante.
    - Ofrece ejemplos prácticos y casos de uso reales.
    - Responde siempre en Español, con claridad pedagógica.
    - Para preguntas teóricas usa consultar_conocimiento.
    - Para ejercicios prácticos usa resolver_ejercicios.
    """


# ─────────────────────────── 6. FastAPI y seguridad ────────────────────────
class Pregunta(BaseModel):
    pregunta: str
    contexto: str = ""


request_timestamps = {}


class SecurityMiddleware(BaseHTTPMiddleware):
    async def dispatch(self, request: Request, call_next):
        # Rate-limit sencillo por IP
        ip = request.client.host if request.client else "unknown"
        now = time.time()
        request_timestamps.setdefault(ip, [])
        request_timestamps[ip] = [t for t in request_timestamps[ip] if now - t < 60]
        if len(request_timestamps[ip]) >= 5:
            return JSONResponse(
                status_code=429,
                content={"error": "Demasiadas solicitudes. Intente más tarde."},
            )

        request_timestamps[ip].append(now)

        # Protección de /consultar (solo JWT)
        if request.url.path == "/consultar":
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


app_fastapi = FastAPI()
app = app_fastapi
app_fastapi.add_middleware(SecurityMiddleware)

app_fastapi.add_middleware(
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


# ──────────────────────── Endpoints ─────────────────────────────────────────
@app_fastapi.get("/health")
async def health():
    return {"status": "ok"}


@app_fastapi.post("/token")
async def generar_token():
    if not JWT_SECRET:
        raise HTTPException(status_code=500, detail="JWT_SECRET no configurado")

    token = jwt.encode(
        {"sub": "usuario_autenticado"}, JWT_SECRET, algorithm=JWT_ALGORITHM
    )
    return {"access_token": token, "token_type": "bearer"}


@app_fastapi.post("/consultar")
async def endpoint_consultar(
    pregunta: Pregunta,
    request: Request,
    x_user_id: str | None = Header(default=None, alias="X-User-Id"),
):
    try:
        # Determinar si es una pregunta teórica o un ejercicio práctico
        texto = (pregunta.pregunta or "").lower()
        keywords_ejercicio = [
            "crear tabla",
            "insert",
            "select",
            "update",
            "delete",
            "join",
            "diseñar base",
            "modelo",
            "ejercicio",
            "sql",
            "query",
            "consulta sql",
            "escribir",
            "implementar",
        ]

        es_ejercicio = any(k in texto for k in keywords_ejercicio)

        if es_ejercicio:
            salida = resolver_ejercicios(pregunta.pregunta, pregunta.contexto)
        else:
            salida = consultar_conocimiento(pregunta.pregunta, pregunta.contexto)

        # Determine user id from Authorization JWT (preferred) or header fallback
        uid: int | None = None
        auth = request.headers.get("Authorization", "")
        if auth.startswith("Bearer "):
            token_jwt = auth.replace("Bearer ", "")
            try:
                if JWT_SECRET:
                    payload = jwt.decode(
                        token_jwt, JWT_SECRET, algorithms=[JWT_ALGORITHM]
                    )
                    sub = payload.get("sub")
                    if isinstance(sub, (int, float)):
                        uid = int(sub)
                    elif isinstance(sub, str) and sub.isdigit():
                        uid = int(sub)
            except JWTError:
                uid = None
        if uid is None and x_user_id:
            try:
                uid = int(x_user_id)
            except ValueError:
                uid = None

        return PlainTextResponse(content=str(salida).strip())
    except Exception as e:
        return JSONResponse(content={"error": str(e)}, status_code=500)


# ──────────────────────────── Ejecutar local ───────────────────────────────
if __name__ == "__main__":
    import uvicorn

    port_str = os.getenv("PORT") or "8100"
    port = int(port_str)
    uvicorn.run("agent:app", host="0.0.0.0", port=port, reload=True)
