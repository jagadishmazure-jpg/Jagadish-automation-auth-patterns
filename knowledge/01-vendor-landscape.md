# Vendor landscape: workload automation platforms

Notes from studying how enterprise automation platforms handle authentication
to target systems. Written in my own words; vendors credited by name only.

## What these platforms do

Workload automation platforms (Stonebranch, BMC Control-M and peers) run
scheduled and event-driven jobs across hybrid estates: on-prem servers, cloud
accounts, ERPs, databases. A single nightly batch can touch a dozen systems,
each with its own auth idiom. The platform's job is to hold credentials
centrally, inject them at run time, and rotate them without breaking jobs.

## How they authenticate (patterns observed)

- **Central credential store.** Agents fetch credentials at job start instead
  of storing them on every host. The store is the control point for rotation
  and audit.
- **Per-target connection profiles.** A job definition names a profile
  ("SAP PRD client 100", "Oracle wallet PROD_DB"), not a password. The
  password lives in exactly one place.
- **Least-privilege service accounts.** Each target system gets a dedicated
  account with only the permissions its jobs need -- never a shared admin.
- **Certificate-based host auth** for agent-to-server communication, so a
  rogue host cannot impersonate the scheduler.

## What this repo takes from them

The vault module mirrors the central-store idea; the SAP/Oracle/ServiceNow
modules mirror per-target profiles; the rotation module mirrors the
zero-downtime rotation these platforms advertise. The agentic-AI modules go
one step further: where the vendors govern *jobs*, this repo also governs
*agents* calling tools, because agents choose their targets at run time and
jobs do not.
