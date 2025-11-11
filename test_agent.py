# Test Script for Azure AI Foundry Agent
import os
import requests
from dotenv import load_dotenv

load_dotenv()

AGENT_API_URL = os.getenv("AGENT_API_URL", "http://localhost:8100")


def test_health():
    """Test health endpoint"""
    print("\n🔍 Testing /health endpoint...")
    try:
        response = requests.get(f"{AGENT_API_URL}/health", timeout=10)
        print(f"Status: {response.status_code}")
        print(f"Response: {response.json()}")
        return response.ok
    except Exception as e:
        print(f"❌ Error: {e}")
        return False


def test_token():
    """Test token generation"""
    print("\n🔑 Testing /token endpoint...")
    try:
        response = requests.post(f"{AGENT_API_URL}/token", timeout=10)
        print(f"Status: {response.status_code}")
        data = response.json()
        print(f"Token received: {data.get('access_token', '')[:20]}...")
        return data.get("access_token") if response.ok else None
    except Exception as e:
        print(f"❌ Error: {e}")
        return None


def test_consultar(token):
    """Test chat endpoint"""
    print("\n💬 Testing /consultar endpoint...")
    try:
        headers = {
            "Authorization": f"Bearer {token}",
            "Content-Type": "application/json",
        }
        payload = {"pregunta": "¿Qué es una base de datos relacional?", "contexto": ""}
        response = requests.post(
            f"{AGENT_API_URL}/consultar", headers=headers, json=payload, timeout=60
        )
        print(f"Status: {response.status_code}")
        print(f"Response: {response.text[:200]}...")
        return response.ok
    except Exception as e:
        print(f"❌ Error: {e}")
        return False


def test_vector_stores(token):
    """Test vector stores listing"""
    print("\n📚 Testing /vector-stores endpoint...")
    try:
        headers = {"Authorization": f"Bearer {token}"}
        response = requests.get(
            f"{AGENT_API_URL}/vector-stores", headers=headers, timeout=10
        )
        print(f"Status: {response.status_code}")
        data = response.json()
        stores = data.get("vector_stores", [])
        print(f"Found {len(stores)} vector store(s)")
        for store in stores:
            print(
                f"  - {store.get('name')} ({store.get('file_counts', {}).get('total', 0)} files)"
            )
        return response.ok
    except Exception as e:
        print(f"❌ Error: {e}")
        return False


def main():
    print("=" * 60)
    print("🧪 UFPS Tutor Agent - Test Suite")
    print("=" * 60)
    print(f"Testing against: {AGENT_API_URL}")

    results = []

    # Test 1: Health check
    health_ok = test_health()
    results.append(("Health Check", health_ok))

    if not health_ok:
        print("\n❌ Health check failed. Make sure the server is running:")
        print("   python agent_v2.py")
        return

    # Test 2: Token generation
    token = test_token()
    results.append(("Token Generation", token is not None))

    if not token:
        print("\n❌ Token generation failed. Check JWT_SECRET in .env")
        return

    # Test 3: Chat endpoint
    chat_ok = test_consultar(token)
    results.append(("Chat Endpoint", chat_ok))

    # Test 4: Vector stores
    vs_ok = test_vector_stores(token)
    results.append(("Vector Stores", vs_ok))

    # Summary
    print("\n" + "=" * 60)
    print("📊 Test Results Summary")
    print("=" * 60)
    for test_name, passed in results:
        status = "✅ PASS" if passed else "❌ FAIL"
        print(f"{status} - {test_name}")

    all_passed = all(passed for _, passed in results)
    if all_passed:
        print("\n🎉 All tests passed!")
    else:
        print("\n⚠️  Some tests failed. Check the errors above.")


if __name__ == "__main__":
    main()
