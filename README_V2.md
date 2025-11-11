# UFPS Tutor Agent V2 - Azure AI Foundry Migration

## 🚀 Overview

This is the upgraded backend for UFPS Tutor using **Azure AI Foundry Agents**. It replaces the custom RAG implementation with Microsoft's managed agent service.

## 🔑 Key Features

- ✅ **No Azure CLI required** - Uses Service Principal authentication for production
- ✅ **Vector Store CRUD** - Teachers can upload/manage PDF and PPTX files
- ✅ **Conversation threads** - Maintains context per user
- ✅ **Docker-ready** - Deployable to Render, Azure, or any container service
- ✅ **Secure** - JWT authentication, rate limiting, CORS protection

## 📋 Prerequisites

### 1. Create a Service Principal in Azure

```bash
# Login to Azure (one-time setup on your local machine)
az login

# Create a service principal
az ad sp create-for-rbac --name "ufpstutor-agent-sp" --role "Azure AI Project Manager" \
  --scopes "/subscriptions/69201b32-1620-4e60-a474-4224ff4c7133/resourceGroups/247rrepuestos/providers/Microsoft.CognitiveServices/accounts/2477repuestos-whatsapp"
```

This will output:
```json
{
  "appId": "your-client-id",
  "displayName": "ufpstutor-agent-sp",
  "password": "your-client-secret",
  "tenant": "your-tenant-id"
}
```

### 2. Configure Environment Variables

Update `.env` with your service principal credentials:

```env
# Azure AI Foundry Agent Configuration
AZURE_EXISTING_AGENT_ID="asst_HZWIkjOTZ7ow6QOtoK3LBCLj"
AZURE_EXISTING_AIPROJECT_ENDPOINT="https://2477repuestos-whatsapp.services.ai.azure.com/api/projects/2477repuestos-whatsapp-project"

# Service Principal (from step 1)
AZURE_CLIENT_ID="your-client-id"
AZURE_TENANT_ID="your-tenant-id"
AZURE_CLIENT_SECRET="your-client-secret"

# JWT Security
JWT_SECRET="change-this-to-random-secret-in-production"
JWT_ALGORITHM="HS256"

# Server
PORT="8100"
```

## 🏃 Running Locally

```bash
# Install dependencies
pip install -r requirements-v2.txt

# Run the server
python agent_v2.py
```

The server will start at `http://localhost:8100`

## 🐳 Docker Deployment

### Build and run locally

```bash
docker build -t ufpstutor-agent .
docker run -p 8100:8100 --env-file .env ufpstutor-agent
```

### Deploy to Render

1. **Push to GitHub**
2. **Connect Render to your repo**
3. **Set environment variables** in Render dashboard:
   - `AZURE_EXISTING_AGENT_ID`
   - `AZURE_EXISTING_AIPROJECT_ENDPOINT`
   - `AZURE_CLIENT_ID`
   - `AZURE_TENANT_ID`
   - `AZURE_CLIENT_SECRET`
   - `JWT_SECRET` (auto-generate)

Render will automatically use the `render.yaml` blueprint.

## 📡 API Endpoints

### Public Endpoints

- `GET /health` - Health check
- `POST /token` - Get JWT token

### Protected Endpoints (require Bearer token)

#### Chat
- `POST /consultar` - Send a question to the agent
  ```json
  {
    "pregunta": "¿Qué es una base de datos relacional?",
    "contexto": ""
  }
  ```

#### Vector Store Management (for teachers)
- `GET /vector-stores` - List all vector stores
- `GET /vector-stores/{id}/files` - List files in a vector store
- `POST /vector-stores/{id}/files` - Upload PDF/PPTX file
- `DELETE /vector-stores/{id}/files/{file_id}` - Delete a file
- `POST /vector-stores/{id}/clear` - Remove all files

## 🔧 Frontend Integration

Update `NEXT_PUBLIC_AGENT_API_URL` in frontend `.env`:

```env
# Development
NEXT_PUBLIC_AGENT_API_URL=http://localhost:8100

# Production
NEXT_PUBLIC_AGENT_API_URL=https://your-render-app.onrender.com
```

## 🛡️ Security Notes

1. **Never commit `.env` with real credentials**
2. **Rotate JWT_SECRET regularly**
3. **Use HTTPS in production**
4. **Monitor Azure costs** - AI Foundry charges per token/file storage

## 📚 Additional Resources

- [Azure AI Foundry Agents Docs](https://learn.microsoft.com/en-us/azure/ai-foundry/agents/)
- [Service Principal Authentication](https://learn.microsoft.com/en-us/azure/ai-services/authentication)
- [Render Docker Deployment](https://render.com/docs/docker)

## 🐛 Troubleshooting

### "ResourceNotFound: Subdomain does not map to a resource"
- Check that `AZURE_EXISTING_AIPROJECT_ENDPOINT` is correct
- Verify service principal has "Azure AI Project Manager" role

### "Authentication failed"
- Confirm service principal credentials are correct
- Check that the service principal has proper role assignment

### "Vector store not found"
- Ensure your agent has a file search tool configured in Azure AI Foundry
- Check that vector stores are attached to the agent

## 🔄 Migration from Old System

The old `agent.py` used:
- Custom RAG with ChromaDB
- Local PDF processing
- Azure OpenAI API directly

The new `agent_v2.py` uses:
- Azure AI Foundry managed agent
- Cloud-based vector stores
- No local PDF processing needed
- Better scalability and reliability

## 📝 License

MIT
