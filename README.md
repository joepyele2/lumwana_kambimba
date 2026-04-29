# Road Construction Dashboard

A professional road construction project tracking dashboard with real-time multi-user support.

## Features
- Daily Progress Reports (DPR) with approval workflow
- Weekly and Monthly planning with auto-tracked targets
- Gantt schedule, BOQ tracking, Equipment register
- Team roster, Sickness log, Files & Folders
- PDF/JPG export for all reports
- Role-based access (Admin, Supervisor, Foreman)

## Deployment on Railway

1. Create account at railway.app
2. New Project → Deploy from GitHub
3. Upload this folder to GitHub first
4. Set environment variables:
   - ADMIN_EMAIL=your@email.com
   - ADMIN_PASSWORD=YourSecurePassword123!
   - SESSION_SECRET=any-random-string-here

## Default Login
After deployment, log in with the ADMIN_EMAIL and ADMIN_PASSWORD you set.

## Adding Team Members
Go to USERS tab (admin only) to add foreman and supervisor accounts.
