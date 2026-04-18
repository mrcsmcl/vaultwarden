use rocket::serde::json::Json;
use serde_json::{json, Value};

use crate::{api::JsonResult, error::Error, http_client::make_http_request, CONFIG};
use reqwest::Method;

pub async fn fallback_breach(username: &str) -> JsonResult {
    let username: String = url::form_urlencoded::byte_serialize(username.as_bytes()).collect();

    let primary_provider = CONFIG.breach_provider().to_lowercase();
    let all_automated = vec!["hibp_unifiedsearch", "xposedornot"];

    let mut try_list = vec![];
    if all_automated.contains(&primary_provider.as_str()) {
        try_list.push(primary_provider);
    }
    if CONFIG.enable_hibp_fallback() {
        for p in &all_automated {
            if !try_list.contains(&p.to_string()) {
                try_list.push(p.to_string());
            }
        }
    }

    let mut fallback_messages = Vec::new();

    for current_provider in try_list {
        match current_provider.as_str() {
            "xposedornot" => match fetch_xposedornot(&username).await {
                Ok(mut data) => {
                    if !fallback_messages.is_empty() {
                        let msg = format!(
                            "Previous failures: {}. Results successfully \
                             obtained via XposedOrNot.",
                            fallback_messages.join(" -> ")
                        );
                        data.insert(
                            0,
                            json!({
                                "name": "Provider Fallback",
                                "title": "Automatic Fallback Warning",
                                "domain": "",
                                "breachDate": "1970-01-01T00:00:00Z",
                                "addedDate": "1970-01-01T00:00:00Z",
                                "description": msg,
                                "logoPath": "vw_static/fallback.jpg",
                                "pwnCount": 0,
                                "dataClasses": ["System Alert"]
                            }),
                        );
                    }
                    return Ok(Json(Value::Array(data)));
                }
                Err(404) => {
                    if !fallback_messages.is_empty() {
                        let msg = format!(
                            "Previous failures: {}.<br/><br/><strong>No breaches \
                             found in the secondary provider.</strong>",
                            fallback_messages.join(" -> ")
                        );
                        return Ok(Json(json!([{
                            "name": "Provider Fallback",
                            "title": "Automatic Fallback Warning",
                            "domain": "",
                            "breachDate": "1970-01-01T00:00:00Z",
                            "addedDate": "1970-01-01T00:00:00Z",
                            "description": msg,
                            "logoPath": "vw_static/fallback.jpg",
                            "pwnCount": 0,
                            "dataClasses": ["System Alert"]
                        }])));
                    }
                    return Err(Error::empty().with_code(404));
                }
                Err(e) => {
                    fallback_messages.push(format!("xposedornot Error {e}"));
                }
            },
            "hibp_unifiedsearch" => match fetch_unifiedsearch(&username).await {
                Ok(mut data) => {
                    if !fallback_messages.is_empty() {
                        let msg = format!(
                            "Previous failures: {}. Results successfully \
                             obtained via HIBP UnifiedSearch.",
                            fallback_messages.join(" -> ")
                        );
                        data.insert(
                            0,
                            json!({
                                "name": "Provider Fallback",
                                "title": "Automatic Fallback Warning",
                                "domain": "",
                                "breachDate": "1970-01-01T00:00:00Z",
                                "addedDate": "1970-01-01T00:00:00Z",
                                "description": msg,
                                "logoPath": "vw_static/fallback.jpg",
                                "pwnCount": 0,
                                "dataClasses": ["System Alert"]
                            }),
                        );
                    }
                    return Ok(Json(Value::Array(data)));
                }
                Err(404) => {
                    if !fallback_messages.is_empty() {
                        let msg = format!(
                            "Previous failures: {}.<br/><br/><strong>No breaches \
                             found in the secondary provider.</strong>",
                            fallback_messages.join(" -> ")
                        );
                        return Ok(Json(json!([{
                            "name": "Provider Fallback",
                            "title": "Automatic Fallback Warning",
                            "domain": "",
                            "breachDate": "1970-01-01T00:00:00Z",
                            "addedDate": "1970-01-01T00:00:00Z",
                            "description": msg,
                            "logoPath": "vw_static/fallback.jpg",
                            "pwnCount": 0,
                            "dataClasses": ["System Alert"]
                        }])));
                    }
                    return Err(Error::empty().with_code(404));
                }
                Err(e) => {
                    fallback_messages.push(format!("hibp_unifiedsearch Error {e}"));
                }
            },
            _ => {}
        }
    }

    Err(Error::empty().with_code(404))
}

/// Fetch breach data from XposedOrNot (free, no API key required) and map to Bitwarden format.
/// Uses the v1/breach-analytics endpoint which returns structured breach details.
async fn fetch_xposedornot(username: &str) -> Result<Vec<Value>, u16> {
    let url = format!("https://api.xposedornot.com/v1/breach-analytics?email={username}");

    let res = make_http_request(Method::GET, &url).map_err(|_| 500_u16)?.send().await.map_err(|_| 500_u16)?;

    if res.status() == 404 {
        return Err(404);
    }
    if !res.status().is_success() {
        return Err(res.status().as_u16());
    }

    let body: Value = res.json().await.map_err(|_| 500_u16)?;

    // Response structure: { "ExposedBreaches": { "breaches_details": [...] } }
    let breaches = match body.get("ExposedBreaches").and_then(|eb| eb.get("breaches_details")) {
        Some(Value::Array(arr)) => arr,
        _ => return Err(404),
    };

    let mapped: Vec<Value> = breaches
        .iter()
        .map(|b| {
            // xposed_date is a year string (e.g. "2016"), format to ISO 8601
            let breach_date = match b.get("xposed_date").and_then(|d| d.as_str()) {
                Some(year) => format!("{year}-01-01T00:00:00Z"),
                None => "1970-01-01T00:00:00Z".to_string(),
            };

            let added_date = b.get("added").and_then(|d| d.as_str()).unwrap_or("1970-01-01T00:00:00Z").to_string();

            // xposed_data is a semicolon-separated string of data categories
            let data_classes: Vec<String> = b
                .get("xposed_data")
                .and_then(|d| d.as_str())
                .unwrap_or("")
                .split(';')
                .map(|s| s.trim().to_string())
                .filter(|s| !s.is_empty())
                .collect();

            let breach_name = b.get("breach").and_then(|v| v.as_str()).unwrap_or("Unknown");

            json!({
                "name": breach_name,
                "title": breach_name,
                "domain": b.get("domain").and_then(|v| v.as_str()).unwrap_or(""),
                "breachDate": breach_date,
                "addedDate": added_date,
                "description": b.get("details").and_then(|v| v.as_str()).unwrap_or(""),
                "logoPath": b.get("logo").and_then(|v| v.as_str()).map(|s| if s.is_empty() { "vw_static/hibp.png" } else { s }).unwrap_or("vw_static/hibp.png"),
                "pwnCount": b.get("xposed_records").and_then(|v| v.as_u64()).unwrap_or(0),
                "dataClasses": data_classes
            })
        })
        .collect();

    Ok(mapped)
}

/// Fetch breach data from HIBP's unifiedsearch endpoint (no API key required).
/// Note: This endpoint is intended for browser-based access. May be subject to
/// rate limiting or policy changes by HIBP at any time.
async fn fetch_unifiedsearch(username: &str) -> Result<Vec<Value>, u16> {
    let url = format!("https://haveibeenpwned.com/unifiedsearch/{username}");

    let res = make_http_request(Method::GET, &url)
        .map_err(|_| 500_u16)?
        .header(
            "User-Agent",
            "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 \
             (KHTML, like Gecko) Chrome/130.0.0.0 Safari/537.36",
        )
        .header("Accept", "application/json")
        .header("Referer", "https://haveibeenpwned.com/")
        .header("Origin", "https://haveibeenpwned.com")
        .send()
        .await
        .map_err(|_| 500_u16)?;

    if res.status() == 404 {
        return Err(404);
    }
    if !res.status().is_success() {
        return Err(res.status().as_u16());
    }

    let body: Value = res.json().await.map_err(|_| 500_u16)?;

    match body.get("Breaches") {
        Some(Value::Array(breaches)) => Ok(breaches.clone()),
        _ => Err(404),
    }
}
