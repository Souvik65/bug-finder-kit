# Error Handling & Secure Logging — Technical Reference

## 1. RFC 7807 (Problem Details for HTTP APIs) Standard

When returning errors from REST or GraphQL APIs, avoid non-standard custom payloads that inadvertently leak exception names. Implement standard **RFC 7807 Problem Details**:

```json
{
  "type": "https://api.example.com/errors/invalid-order",
  "title": "Invalid Order Parameters",
  "status": 400,
  "detail": "The requested item quantity exceeds available stock.",
  "instance": "/orders/12345/items",
  "invalid-params": [
    {
      "name": "quantity",
      "reason": "Must be less than or equal to 10"
    }
  ],
  "traceId": "9b1deb4d-3b7d-4bad-9bdd-2b0d7b3dcb6d"
}
```

### Key Principles of RFC 7807:
- Standardized top-level keys (`type`, `title`, `status`, `detail`, `instance`).
- `detail` contains human-readable, safe business explanations, never runtime exception strings.
- `traceId` provides an opaque correlation identifier that matches internal server log entries.

---

## 2. Global Exception Handling Patterns by Language

### Express.js Global Error Boundary
```javascript
// Ensure this middleware is registered AFTER all app.use() routes
app.use((err, req, res, next) => {
    const errorId = crypto.randomUUID();
    
    // Log full detail internally
    logger.error({
        errorId,
        message: err.message,
        stack: err.stack,
        path: req.path,
        method: req.method
    });

    // Send safe payload to client
    res.status(err.status || 500).json({
        title: err.status === 404 ? "Not Found" : "Internal Server Error",
        status: err.status || 500,
        detail: err.isOperational ? err.message : "An unexpected server error occurred.",
        traceId: errorId
    });
});
```

### Python / FastAPI Custom Exception Handler
```python
from fastapi import FastAPI, Request, status
from fastapi.responses import JSONResponse
import logging, uuid

app = FastAPI()
logger = logging.getLogger("uvicorn.error")

@app.exception_handler(Exception)
async def global_exception_handler(request: Request, exc: Exception):
    error_id = str(uuid.uuid4())
    logger.error(f"Error ID: {error_id} - Path: {request.url.path}", exc_info=True)
    
    return JSONResponse(
        status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
        content={
            "title": "Internal Server Error",
            "status": 500,
            "detail": "An internal error occurred. Please quote the reference ID.",
            "errorId": error_id
        }
    )
```

### Spring Boot ControllerAdvice
```java
@ControllerAdvice
public class GlobalExceptionHandler {
    private static final Logger logger = LoggerFactory.getLogger(GlobalExceptionHandler.class);

    @ExceptionHandler(Exception.class)
    public ResponseEntity<ProblemDetail> handleAllExceptions(Exception ex, HttpServletRequest request) {
        String errorId = UUID.randomUUID().toString();
        logger.error("Error ID: {} - URI: {}", errorId, request.getRequestURI(), ex);

        ProblemDetail problem = ProblemDetail.forStatusAndDetail(
            HttpStatus.INTERNAL_SERVER_ERROR,
            "An unexpected error occurred. Please contact support with the trace ID."
        );
        problem.setTitle("Internal Server Error");
        problem.setProperty("traceId", errorId);

        return ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR).body(problem);
    }
}
```

---

## 3. Log Redaction Implementations

### Node.js Pino Redact Config
```javascript
const pino = require('pino');

const logger = pino({
    redact: {
        paths: [
            'req.headers.authorization',
            'req.headers.cookie',
            'password',
            '*.password',
            'token',
            '*.token',
            'creditCard',
            '*.cardNumber'
        ],
        censor: '[CONFIDENTIAL]'
    }
});
```

### Python Structlog Filtering
```python
import structlog

def redact_sensitive_data(logger, method_name, event_dict):
    SENSITIVE_KEYS = {"password", "secret", "token", "authorization", "api_key"}
    for key in list(event_dict.keys()):
        if any(sensitive in key.lower() for sensitive in SENSITIVE_KEYS):
            event_dict[key] = "[REDACTED]"
    return event_dict

structlog.configure(
    processors=[
        redact_sensitive_data,
        structlog.processors.JSONRenderer()
    ]
)
```
