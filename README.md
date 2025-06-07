# Apache Antibot Module

## Overview

This Apache module provides antibot protection by communicating with an external antibot backend. It intercepts all requests configured in apache to be challenges and forwards them to a backend service for verification, serving challenge pages when needed.

## How It Works

1. **All Requests**: Every incoming request configured to be challenged with the antibot service is sent to the auth backend
2. **Backend Response 200**: Request continues normally through Apache
3. **Backend Response 429**: Serves challenge HTML page to client
4. **Challenge POST**: POST requests with `?challenge` parameter are forwarded to antibot backend

