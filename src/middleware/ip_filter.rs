use actix_web::{
    dev::{forward_ready, Service, ServiceRequest, ServiceResponse, Transform},
    Error, HttpResponse,
};
use std::collections::HashSet;
use std::future::{ready, Future, Ready};
use std::net::IpAddr;
use std::pin::Pin;
use std::sync::Arc;

/// IP Whitelist/Blacklist middleware
pub struct IpFilter {
    whitelist: Arc<HashSet<String>>,
    blacklist: Arc<HashSet<String>>,
    enabled: bool,
}

impl IpFilter {
    pub fn new(whitelist: Vec<String>, blacklist: Vec<String>, enabled: bool) -> Self {
        Self {
            whitelist: Arc::new(whitelist.into_iter().collect()),
            blacklist: Arc::new(blacklist.into_iter().collect()),
            enabled,
        }
    }

    #[allow(dead_code)]
    fn is_allowed(&self, ip: &str) -> bool {
        if !self.enabled {
            return true;
        }

        // Blacklist kontrolü
        if self.blacklist.contains(ip) {
            return false;
        }

        // CIDR kontrolü (basit)
        for blocked in self.blacklist.iter() {
            if ip_matches_cidr(ip, blocked) {
                return false;
            }
        }

        // Whitelist boşsa herkese izin ver
        if self.whitelist.is_empty() {
            return true;
        }

        // Whitelist'te mi kontrol et
        if self.whitelist.contains(ip) {
            return true;
        }

        for allowed in self.whitelist.iter() {
            if ip_matches_cidr(ip, allowed) {
                return true;
            }
        }

        false
    }
}

/// Basit CIDR eşleştirmesi (ör: 192.168.0.0/16)
fn ip_matches_cidr(ip: &str, cidr: &str) -> bool {
    if !cidr.contains('/') {
        return ip == cidr;
    }

    let parts: Vec<&str> = cidr.split('/').collect();
    if parts.len() != 2 {
        return false;
    }

    let cidr_ip: IpAddr = match parts[0].parse() {
        Ok(ip) => ip,
        Err(_) => return false,
    };

    let prefix_len: u32 = match parts[1].parse() {
        Ok(p) => p,
        Err(_) => return false,
    };

    let target_ip: IpAddr = match ip.parse() {
        Ok(ip) => ip,
        Err(_) => return false,
    };

    match (cidr_ip, target_ip) {
        (IpAddr::V4(cidr_v4), IpAddr::V4(target_v4)) => {
            let cidr_bits = u32::from(cidr_v4);
            let target_bits = u32::from(target_v4);
            let mask = if prefix_len >= 32 { u32::MAX } else { !((1u32 << (32 - prefix_len)) - 1) };
            (cidr_bits & mask) == (target_bits & mask)
        }
        _ => false,
    }
}

impl<S, B> Transform<S, ServiceRequest> for IpFilter
where
    S: Service<ServiceRequest, Response = ServiceResponse<B>, Error = Error> + 'static,
    B: 'static,
{
    type Response = ServiceResponse<actix_web::body::EitherBody<B>>;
    type Error = Error;
    type Transform = IpFilterMiddleware<S>;
    type InitError = ();
    type Future = Ready<Result<Self::Transform, Self::InitError>>;

    fn new_transform(&self, service: S) -> Self::Future {
        ready(Ok(IpFilterMiddleware {
            service,
            whitelist: self.whitelist.clone(),
            blacklist: self.blacklist.clone(),
            enabled: self.enabled,
        }))
    }
}

pub struct IpFilterMiddleware<S> {
    service: S,
    whitelist: Arc<HashSet<String>>,
    blacklist: Arc<HashSet<String>>,
    enabled: bool,
}

impl<S> IpFilterMiddleware<S> {
    fn is_allowed(&self, ip: &str) -> bool {
        if !self.enabled {
            return true;
        }

        if self.blacklist.contains(ip) {
            return false;
        }

        for blocked in self.blacklist.iter() {
            if ip_matches_cidr(ip, blocked) {
                return false;
            }
        }

        if self.whitelist.is_empty() {
            return true;
        }

        if self.whitelist.contains(ip) {
            return true;
        }

        for allowed in self.whitelist.iter() {
            if ip_matches_cidr(ip, allowed) {
                return true;
            }
        }

        false
    }
}

impl<S, B> Service<ServiceRequest> for IpFilterMiddleware<S>
where
    S: Service<ServiceRequest, Response = ServiceResponse<B>, Error = Error> + 'static,
    B: 'static,
{
    type Response = ServiceResponse<actix_web::body::EitherBody<B>>;
    type Error = Error;
    type Future = Pin<Box<dyn Future<Output = Result<Self::Response, Self::Error>>>>;

    forward_ready!(service);

    fn call(&self, req: ServiceRequest) -> Self::Future {
        let ip = req
            .peer_addr()
            .map(|addr| addr.ip().to_string())
            .unwrap_or_else(|| "unknown".to_string());

        if !self.is_allowed(&ip) {
            tracing::warn!("IP blocked: {}", ip);
            return Box::pin(async move {
                let response = HttpResponse::Forbidden()
                    .json(serde_json::json!({
                        "error": "Access denied",
                        "message": "Your IP address is not allowed"
                    }));
                Ok(req.into_response(response).map_into_right_body())
            });
        }

        let fut = self.service.call(req);
        Box::pin(async move {
            let res = fut.await?;
            Ok(res.map_into_left_body())
        })
    }
}
