# Mohd Shoaib

Role: **Dashboard, authentication and review-workflow developer**

## Primary files

| File | Assigned responsibility |
| --- | --- |
| `kernelguard/web.py` | Build activity dashboard, event, alert and evidence routes. |
| `kernelguard/auth.py` | Implement administrator accounts, login sessions, password hashing and CSRF protection. |
| `kernelguard/reviews.py` | Validate alert acknowledgement/reopening and device enrollment decisions. |
| `kernelguard/inventory/routes.py` | Build inventory and USB-device routes with pagination and readable relationships. |
| `kernelguard/templates/base.html` | Provide shared page navigation and layout. |
| `kernelguard/templates/dashboard.html` | Present status, rules and recent alerts. |
| `kernelguard/templates/events.html` | Present filtered normalized events. |
| `kernelguard/templates/alert.html` | Present alert evidence and immutable review history. |
| `kernelguard/templates/inventory.html` | Present users, sessions, processes and devices. |
| `kernelguard/templates/device.html` | Present USB history and approval/revocation controls. |
| `kernelguard/templates/login.html` | Present administrator login. |
| `kernelguard/static/style.css` | Style the dashboard and responsive screens. |
| `linux/services/kernelguard-web.service` | Run the local dashboard as an unprivileged service. |
| `scripts/start.ps1` | Start the complete local demonstration. |
| `scripts/start-demo.ps1` | Retain the compatible demo-launch alias. |
| `docs/OPERATIONS.md` | Explain startup, login and the complete demonstration sequence. |
| `docs/SERVICES.md` | Explain optional service installation and separation of privileges. |

## Shared files

| File | Shoaib's section |
| --- | --- |
| `kernelguard/inventory/schema.py` | Tables queried by inventory/device pages. Primary database owner: Ahmed. |
| `tests/test_activity_reviews.py` | Authentication, CSRF and alert-review UI behavior. Rule assertions are shared with Ankit. |
| `tests/test_inventory.py` | Inventory routes and device enrollment/revocation workflow. Shared with Arshpreet and Ahmed. |
| `requirements.txt` | Flask, Werkzeug and Waitress dependencies. Team-level file. |
| `docs/ACCEPTANCE.md` | Dashboard, CSRF and review-workflow evidence. Team-level file. |

## What Shoaib should explain

- Dashboard navigation, filters and evidence links.
- Administrator login and secure password storage.
- CSRF protection and session expiry.
- Alert acknowledgement/reopening with immutable history.
- USB approval/revocation and why approval affects future observations only.
