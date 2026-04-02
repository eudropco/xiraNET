/// GraphQL Gateway — schema proxy + request routing
use actix_web::{web, HttpRequest, HttpResponse};
use crate::registry::ServiceRegistry;

/// GraphQL proxy handler
/// POST /graphql → route to appropriate upstream based on query analysis
pub async fn graphql_handler(
    _req: HttpRequest,
    body: web::Bytes,
    registry: web::Data<ServiceRegistry>,
) -> HttpResponse {
    let body_str = String::from_utf8_lossy(&body);

    // Parse GraphQL request
    let gql_request: serde_json::Value = match serde_json::from_str(&body_str) {
        Ok(v) => v,
        Err(_) => {
            return HttpResponse::BadRequest().json(serde_json::json!({
                "errors": [{"message": "Invalid GraphQL request body"}]
            }));
        }
    };

    let query = gql_request.get("query").and_then(|q| q.as_str()).unwrap_or("");
    let _operation_name = gql_request.get("operationName").and_then(|o| o.as_str());
    let _variables = gql_request.get("variables");

    // Route'u belirle — servis prefix'ine göre
    // Convention: __typename veya type adından servis belirle
    let target_service = determine_target_service(query, &registry);

    match target_service {
        Some(service) => {
            // Upstream'e proxy
            let client = reqwest::Client::new();
            let upstream_url = format!("{}/graphql", service.upstream);

            match client.post(&upstream_url)
                .header("Content-Type", "application/json")
                .body(body.to_vec())
                .send()
                .await
            {
                Ok(resp) => {
                    let status = resp.status();
                    match resp.bytes().await {
                        Ok(body) => {
                            HttpResponse::build(actix_web::http::StatusCode::from_u16(status.as_u16()).unwrap())
                                .content_type("application/json")
                                .insert_header(("X-Proxied-By", "XIRA-GraphQL"))
                                .body(body)
                        }
                        Err(e) => HttpResponse::BadGateway().json(serde_json::json!({
                            "errors": [{"message": format!("Upstream read error: {}", e)}]
                        })),
                    }
                }
                Err(e) => HttpResponse::BadGateway().json(serde_json::json!({
                    "errors": [{"message": format!("Upstream unreachable: {}", e)}]
                })),
            }
        }
        None => {
            // Schema introspection — tüm servislerin schema'larını birleştir
            if query.contains("__schema") || query.contains("__type") {
                return serve_combined_schema(&registry).await;
            }

            HttpResponse::NotFound().json(serde_json::json!({
                "errors": [{"message": "No upstream service found for this GraphQL query"}]
            }))
        }
    }
}

/// Query'den hedef servisi belirle
fn determine_target_service(
    query: &str,
    registry: &ServiceRegistry,
) -> Option<crate::registry::models::ServiceEntry> {
    let services = registry.list_all();

    // Convention: Query type adı servis prefix ile eşleşir
    // Örn: "query { users { ... } }" → /users prefix'li servise yönlendir
    for service in &services {
        let prefix = service.prefix.trim_start_matches('/');
        if query.contains(prefix) {
            return Some(service.clone());
        }
    }

    // Fallback: ilk servise yönlendir
    services.into_iter().next()
}

/// Birleşik schema döndür
async fn serve_combined_schema(registry: &ServiceRegistry) -> HttpResponse {
    let services = registry.list_all();
    let mut types = Vec::new();

    for service in &services {
        types.push(serde_json::json!({
            "name": service.name,
            "fields": [{
                "name": "id", "type": { "name": "ID" }
            }],
            "upstream": service.upstream,
        }));
    }

    HttpResponse::Ok().json(serde_json::json!({
        "data": {
            "__schema": {
                "queryType": { "name": "Query" },
                "types": types,
                "description": "XIRA federated GraphQL schema",
            }
        }
    }))
}
