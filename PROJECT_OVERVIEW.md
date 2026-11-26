# Project Overview

## Title
**Web Application Penetration Testing and Vulnerability Assessment (WAPT)**

## Problem statement
Web applications may expose weak security configuration, unsafe transport settings, sensitive resources, and information that increases attack surface. Small teams and students need a clear way to inspect common baseline controls and document remediation work.

## Proposed solution
WAPT is a locally hosted dashboard that accepts an explicitly authorized target, performs a limited set of non-destructive HTTP/TLS checks, stores observations, classifies them by severity, and creates downloadable reports.

## Main objectives
- Identify common web security misconfigurations.
- Present technical evidence and practical remediation guidance.
- Maintain a repeatable scan history.
- Generate structured JSON and CSV assessment reports.
- Enforce a clear authorization requirement and bounded scan scope.

## Architecture
Browser UI → Flask routes and authentication → target validation → safe HTTP/TLS scanner → findings/severity engine → SQLite storage → report/export routes.

## Expected output
A dashboard with overall metrics, a target assessment form, scan history, a report view, severity counts, a heuristic security score, and CSV/JSON downloads.

## Scope disclaimer
The implementation is a safe baseline assessment tool. It is not an automated exploitation framework and does not claim to discover every vulnerability. Findings require manual confirmation.
