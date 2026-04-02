use actix_web::{web, HttpResponse};
use crate::registry::ServiceRegistry;

/// OpenAPI spec aggregation
/// GET /xira/docs — birleşik OpenAPI spec
pub async fn openapi_handler(
    registry: web::Data<ServiceRegistry>,
) -> HttpResponse {
    let services: Vec<serde_json::Value> = registry
        .list_all()
        .iter()
        .map(|svc| {
            serde_json::json!({
                "name": svc.name,
                "prefix": svc.prefix,
                "upstream": svc.upstream,
                "version": svc.version,
                "status": format!("{:?}", svc.status),
            })
        })
        .collect();

    // Birleşik OpenAPI 3.0 spec oluştur
    let spec = serde_json::json!({
        "openapi": "3.0.3",
        "info": {
            "title": "XIRA Platform API",
            "description": "Auto-generated API documentation from registered services",
            "version": env!("CARGO_PKG_VERSION"),
            "contact": {
                "name": "XIRA Admin",
                "url": "/dashboard",
            }
        },
        "servers": [
            {
                "url": "/",
                "description": "Gateway (default)"
            }
        ],
        "paths": build_paths(&registry),
        "components": {
            "securitySchemes": {
                "apiKey": {
                    "type": "apiKey",
                    "in": "header",
                    "name": "X-API-Key"
                },
                "bearer": {
                    "type": "http",
                    "scheme": "bearer",
                    "bearerFormat": "JWT"
                }
            }
        },
        "tags": services.iter().map(|svc| {
            serde_json::json!({
                "name": svc["name"],
                "description": format!("Routes to {} ({})", svc["upstream"], svc["prefix"]),
            })
        }).collect::<Vec<_>>(),
        "x-gateway-services": services,
    });

    HttpResponse::Ok()
        .content_type("application/json")
        .json(spec)
}

/// Swagger UI HTML
pub async fn swagger_ui_handler() -> HttpResponse {
    let html = r#"<!DOCTYPE html>
<html>
<head>
    <title>XIRA Platform — API Documentation</title>
    <meta charset="utf-8"/>
    <meta name="viewport" content="width=device-width, initial-scale=1">
    <link rel="stylesheet" href="https://unpkg.com/swagger-ui-dist@5/swagger-ui.css">
    <style>
        body { margin: 0; background: #1a1a2e; }
        .swagger-ui .topbar { background: #16213e; }
        .swagger-ui .topbar .download-url-wrapper .select-label span { color: #e94560; }
    </style>
</head>
<body>
    <div id="swagger-ui"></div>
    <script src="https://unpkg.com/swagger-ui-dist@5/swagger-ui-bundle.js"></script>
    <script>
        SwaggerUIBundle({
            url: '/xira/docs/spec',
            dom_id: '#swagger-ui',
            deepLinking: true,
            presets: [
                SwaggerUIBundle.presets.apis,
                SwaggerUIBundle.SwaggerUIStandalonePreset
            ],
            layout: "StandaloneLayout",
            tryItOutEnabled: true,
        });
    </script>
</body>
</html>"#;

    HttpResponse::Ok()
        .content_type("text/html; charset=utf-8")
        .body(html)
}

/// Registry'den path'ler oluştur
fn build_paths(registry: &ServiceRegistry) -> serde_json::Value {
    let mut paths = serde_json::Map::new();

    for svc in registry.list_all() {
        let path = format!("{}{{path}}", svc.prefix);
        let methods = serde_json::json!({
            "get": {
                "tags": [svc.name],
                "summary": format!("GET {}", svc.prefix),
                "description": format!("Proxied to {}", svc.upstream),
                "parameters": [
                    {
                        "name": "path",
                        "in": "path",
                        "required": true,
                        "schema": { "type": "string" }
                    }
                ],
                "responses": {
                    "200": { "description": "Success" },
                    "502": { "description": "Upstream error" },
                    "503": { "description": "Service unavailable (circuit breaker)" }
                }
            },
            "post": {
                "tags": [svc.name],
                "summary": format!("POST {}", svc.prefix),
                "description": format!("Proxied to {}", svc.upstream),
                "parameters": [
                    {
                        "name": "path",
                        "in": "path",
                        "required": true,
                        "schema": { "type": "string" }
                    }
                ],
                "requestBody": {
                    "content": {
                        "application/json": {
                            "schema": { "type": "object" }
                        }
                    }
                },
                "responses": {
                    "200": { "description": "Success" },
                    "502": { "description": "Upstream error" }
                }
            }
        });

        paths.insert(path, methods);
    }

    // Admin API paths
    paths.insert("/xira/services".to_string(), serde_json::json!({
        "get": {
            "tags": ["Admin"],
            "summary": "List all registered services",
            "security": [{"apiKey": []}],
            "responses": { "200": { "description": "Service list" } }
        },
        "post": {
            "tags": ["Admin"],
            "summary": "Register a new service",
            "security": [{"apiKey": []}],
            "requestBody": {
                "content": {
                    "application/json": {
                        "schema": {
                            "type": "object",
                            "properties": {
                                "name": { "type": "string" },
                                "prefix": { "type": "string" },
                                "upstream": { "type": "string" },
                            },
                            "required": ["name", "prefix", "upstream"]
                        }
                    }
                }
            },
            "responses": { "201": { "description": "Service registered" } }
        }
    }));

    serde_json::Value::Object(paths)
}
