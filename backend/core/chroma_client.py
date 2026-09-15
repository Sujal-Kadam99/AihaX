"""ChromaDB client for long-term learning across scans."""

from typing import Any, Optional

import chromadb
from chromadb.config import Settings as ChromaSettings

from backend.core.config import get_settings

_chroma_client: Optional[chromadb.ClientAPI] = None

COLLECTIONS = [
    "confirmed_vulnerabilities",
    "false_positive_patterns",
    "waf_bypass_techniques",
    "login_flow_patterns",
]


def get_chroma() -> chromadb.ClientAPI:
    global _chroma_client
    if _chroma_client is None:
        settings = get_settings()
        _chroma_client = chromadb.PersistentClient(
            path=settings.chroma_path,
            settings=ChromaSettings(anonymized_telemetry=False),
        )
        for name in COLLECTIONS:
            _chroma_client.get_or_create_collection(name)
    return _chroma_client


def query_similar(
    collection_name: str,
    query_text: str,
    n_results: int = 5,
    where: Optional[dict[str, Any]] = None,
) -> list[dict[str, Any]]:
    client = get_chroma()
    collection = client.get_collection(collection_name)
    results = collection.query(
        query_texts=[query_text],
        n_results=n_results,
        where=where,
    )
    items = []
    if results and results["documents"]:
        for i, doc in enumerate(results["documents"][0]):
            items.append({
                "document": doc,
                "metadata": results["metadatas"][0][i] if results["metadatas"] else {},
                "distance": results["distances"][0][i] if results["distances"] else None,
            })
    return items


def upsert_document(
    collection_name: str,
    doc_id: str,
    document: str,
    metadata: dict[str, Any],
) -> None:
    client = get_chroma()
    collection = client.get_collection(collection_name)
    collection.upsert(
        ids=[doc_id],
        documents=[document],
        metadatas=[metadata],
    )
