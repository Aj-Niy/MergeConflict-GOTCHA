# GOTCHA — Hackathon Submission Draft

## Project Title
GOTCHA: Semantic Trust Verification for AI Tools, MCP Servers & Agent Skills

## One-Line Pitch
GOTCHA helps users verify whether an AI tool or MCP skill actually does what its documentation claims by comparing declared capabilities with real code behavior.

## Problem Statement
Modern AI agents increasingly rely on natural-language descriptions of tools, plugins, and skills. These descriptions can be misleading, and hidden behaviors such as data exfiltration, environment access, or unexpected network usage can go unnoticed.

Traditional security checks are not enough because a tool can appear harmless while still performing deceptive or risky actions.

## Solution
GOTCHA analyzes:
- the description or documentation of a tool,
- the underlying source code,
- and the behavioral gap between the two.

It then produces a trust report that highlights hidden capabilities and assigns a risk score.

## What Makes It Innovative
- Combines semantic analysis and code behavior analysis
- Detects undocumented capabilities rather than only known vulnerabilities
- Helps users make safer decisions about AI tools and agent skills
- Presents a clear trust report for human review

## Tech Stack
- Frontend: React, TypeScript, Vite
- Backend: FastAPI, Python
- Analysis: Python AST analysis + LLM-based claim extraction
- Storage: SQLite

## Key Features
- Scan tool descriptions and source code
- Extract claimed capabilities from documentation
- Extract observed behaviors from code
- Compare claims vs behavior
- Generate trust/risk reports
- View scan history and analytics

## Demo Flow
1. Enter a GitHub repository or tool description
2. Submit the scan
3. Review the extracted claims and observed behaviors
4. See the mismatch and risk score
5. Use the report to decide whether the tool is trustworthy

## Why This Matters
As AI agents become more autonomous, trust decisions must go beyond surface-level descriptions. GOTCHA brings transparency to the tool selection process and helps prevent hidden behavior from slipping through.

## Impact
This project improves AI safety by helping developers, researchers, and teams verify whether a tool is actually aligned with its stated purpose before integrating it into their workflows.

## Short Submission Description
GOTCHA is a semantic trust verification platform for AI tools, MCP servers, and agent skills. It compares what a tool claims to do with what its code actually does, surfacing hidden behaviors and risk before the tool is trusted or deployed.

## Optional Judges Pitch
Instead of asking, “Is this tool vulnerable?” GOTCHA asks, “Does this tool do only what it claims to do?” That makes it a practical trust-and-safety layer for the AI ecosystem.
