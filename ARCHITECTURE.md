# ChatApp V2 Architecture

> Living architecture document for ChatApp V2.

---

# Project Vision

Build a modern, maintainable, secure, lightweight real-time private chat application using FastAPI and Vanilla JavaScript while preserving simplicity and performance.

---

# Technology Stack

## Backend

- FastAPI
- SQLAlchemy
- SQLite (current)
- WebSocket
- JWT Authentication

## Frontend

- HTML5
- CSS3
- Vanilla JavaScript

---

# Design Principles

1. Keep the project lightweight.
2. Avoid unnecessary frameworks.
3. Preserve backward compatibility during refactoring.
4. Modularize code without changing behavior.
5. One responsibility per file.
6. Security before new features.
7. Every change must be testable.

---

# Folder Structure

```
ChatApp/

database.py
models.py
main.py

static/

css/
js/
assets/
uploads/
```

---

# Sprint Roadmap

## Sprint 0

Project Audit

Status:
Completed

---

## Sprint 1

Frontend Foundation

Goal:

Convert monolithic frontend into a modular structure.

Status:

In Progress

---

## Sprint 2

Backend Cleanup

Goal:

Refactor FastAPI project into service-oriented modules.

---

## Sprint 3

Security Hardening

Goal:

Authentication
Validation
Uploads
WebSocket security

---

## Sprint 4

UI/UX Redesign

Goal:

Modern messaging interface

---

## Sprint 5

Performance

Goal:

Reduce unnecessary requests
Improve WebSocket lifecycle
Optimize rendering

---

# Coding Standards

## HTML

- Semantic HTML only
- No duplicate IDs
- Minimal inline styles

## CSS

- Reusable classes
- CSS variables
- Component-based organization

## JavaScript

- One module = one responsibility
- Avoid global variables where possible
- Cache DOM elements
- Group related functions

## Backend

- Service-oriented architecture
- Reusable utilities
- Clear separation of routes, models, and business logic

---

# Development Workflow

Architecture
↓

Patch Planning
↓

Implementation

↓

Testing

↓

Review

↓

Commit

↓

Next Patch

---

# Current Sprint

Sprint 1

Current Patch:

Patch 01

Status:

In Progress

---

# Notes

This document evolves together with the project.

Every architectural decision should be documented here before implementation whenever it changes the project's structure or long-term direction.