# Momo Ecosystem

The sovereign developer's answer to cloud-locked AI tools. Designed for Composition. 
This is the root repository for the Momo ecosystem. 

## Ecosystem Components

* **[BORU](./boru/README.md)**: The Immune System / Verification (Sandbox & offline scanner)
* **NUKI** (coming soon): The Local Brain / Memory (Search / RAG engine)
* **SUJI** (coming soon): The Conductor / Terminal Interface 

### The Unix Philosophy
We didn't build a monolithic AI IDE. We built the primitive engines. 
Each tool stands alone to solve a specific problem perfectly, but when used together, they auto-detect each other via Unix Domain Sockets (`/tmp/momo/*.sock`) to create an automated, airtight local AI development environment. 
