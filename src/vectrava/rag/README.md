# rag: RAG pipeline boundary probes

Boundary probes for retrieval-augmented generation pipelines. The rag module
checks the trust boundaries of a RAG system: retrieval scope, document
isolation, citation integrity, and leakage of restricted context across tenant
or user boundaries.

## Status

Early development. No probes are implemented yet.

## Posture

Defensive only. rag probes a pipeline you own or are authorized to assess. It
runs only against targets named in a signed scope file.
