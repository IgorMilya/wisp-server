use axum::{
    Json, Router,
    extract::{Json as JsonExtract, Path, Query},
    http::StatusCode,
    response::IntoResponse,
    routing::{delete, get},
};
use chrono::{TimeZone, Utc};
use futures::TryStreamExt;
use mongodb::Database;
use mongodb::bson::oid::ObjectId;
use mongodb::bson::{DateTime, Document};
use mongodb::{Client, Collection, bson::doc};
use serde::Serializer;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::net::SocketAddr;
use tokio::net::TcpListener;
use tower_http::cors::CorsLayer;
use dotenvy::dotenv;
use std::env;

fn serialize_datetime_as_iso_string<S>(date: &DateTime, serializer: S) -> Result<S::Ok, S::Error>
where
    S: Serializer,
{
    serializer.serialize_str(&date.try_to_rfc3339_string().unwrap_or_else(|_| "Invalid Date".into()))
}


#[derive(Debug, Serialize, Deserialize)]
pub struct BlacklistedNetwork {
    #[serde(rename = "_id")]
    pub id: ObjectId,
    pub ssid: String,
    pub bssid: String,
    pub timestamp: DateTime,
    pub reason: Option<String>,
}

#[derive(Debug, Serialize)]
pub struct BlacklistedNetworkResponse {
    pub id: String,
    pub ssid: String,
    pub bssid: String,
    #[serde(serialize_with = "serialize_datetime_as_iso_string")]
    pub timestamp: DateTime,
    pub reason: Option<String>,
}

#[derive(Debug, Deserialize)]
pub struct NewBlacklistEntry {
    ssid: String,
    bssid: String,
    reason: Option<String>,
}

async fn get_collection() -> mongodb::error::Result<Database> {
    let db_url = env::var("MONGO_DB_URL")
        .expect("MONGO_DB_URL not set in environment variables");

    let client = Client::with_uri_str(db_url)
        .await
        .expect("Failed to connect to MongoDB");
    let db = client.database("WISP-APP");
    Ok(db)
}

async fn get_blacklist(Query(params): Query<HashMap<String, String>>) -> impl IntoResponse {
    let database = get_collection().await.expect("Failed to connect to DB");
    let my_coll: Collection<BlacklistedNetwork> = database.collection("Blacklist");

    let ssid_query = params.get("ssid");
    let date_query = params.get("date");

    let mut filter = doc! {};

    if let Some(ssid) = ssid_query {
        filter.insert("ssid", doc! { "$regex": ssid, "$options": "i" });
    }

    if let Some(date_str) = date_query {
        if let Ok(parsed_date) = chrono::NaiveDate::parse_from_str(date_str, "%Y-%m-%d") {
            let start = Utc.from_utc_datetime(&parsed_date.and_hms_opt(0, 0, 0).unwrap());
            let end = Utc.from_utc_datetime(&parsed_date.and_hms_opt(23, 59, 59).unwrap());

            filter.insert(
                "timestamp",
                doc! {
                    "$gte": DateTime::from_millis(start.timestamp_millis()),
                    "$lte": DateTime::from_millis(end.timestamp_millis()),
                },
            );
        }
    }

    let mut cursor = match my_coll.find(filter).await {
        Ok(cursor) => cursor,
        Err(err) => {
            let body = Json(serde_json::json!({ "error": err.to_string() }));
            return (StatusCode::INTERNAL_SERVER_ERROR, body).into_response();
        }
    };

    let mut results = Vec::new();
    while let Some(doc) = cursor.try_next().await.unwrap_or(None) {
        results.push(BlacklistedNetworkResponse {
            id: doc.id.to_hex(),
            ssid: doc.ssid,
            bssid: doc.bssid,
            timestamp: doc.timestamp,
            reason: doc.reason,
        });
    }

    Json(results).into_response()
}


async fn delete_from_blacklist(Path(id): Path<String>) -> impl IntoResponse {
    let db = get_collection().await.expect("DB connection");
    let coll: Collection<BlacklistedNetwork> = db.collection("Blacklist");

    let obj_id = match ObjectId::parse_str(&id) {
        Ok(oid) => oid,
        Err(_) => {
            return (
                StatusCode::BAD_REQUEST,
                Json(serde_json::json!({"error": "Invalid id"})),
            )
                .into_response();
        }
    };

    match coll.delete_one(doc! { "_id": obj_id }).await {
        Ok(res) if res.deleted_count == 1 => (
            StatusCode::OK,
            Json(serde_json::json!({"status": "deleted"})),
        )
            .into_response(),
        Ok(_) => (
            StatusCode::NOT_FOUND,
            Json(serde_json::json!({"error": "Not found"})),
        )
            .into_response(),
        Err(e) => (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(serde_json::json!({"error": e.to_string()})),
        )
            .into_response(),
    }
}

async fn add_to_blacklist(
    JsonExtract(payload): JsonExtract<NewBlacklistEntry>,
) -> impl IntoResponse {
    let db = get_collection().await.expect("DB connection");
    let coll: Collection<Document> = db.collection("Blacklist");

    let new_doc = doc! {
        "ssid": payload.ssid,
        "bssid": payload.bssid,
        "timestamp": DateTime::now(),
        "reason": payload.reason.unwrap_or("Manually added".into()),
    };

    match coll.insert_one(new_doc).await {
        Ok(_) => (
            StatusCode::CREATED,
            Json(serde_json::json!({"status": "added"})),
        )
            .into_response(),
        Err(e) => (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(serde_json::json!({"error": e.to_string()})),
        )
            .into_response(),
    }
}
// ------------------------------------------------- WHITELIST

#[derive(Debug, Serialize, Deserialize)]
pub struct WhitelistedNetwork {
    #[serde(rename = "_id")]
    pub id: ObjectId,
    pub ssid: String,
    pub bssid: String,
    pub timestamp: DateTime,
}

#[derive(Debug, Serialize)]
pub struct WhitelistedNetworkResponse {
    pub id: String,
    pub ssid: String,
    pub bssid: String,
    #[serde(serialize_with = "serialize_datetime_as_iso_string")]
    pub timestamp: DateTime,
}

#[derive(Debug, Deserialize)]
pub struct NewWhitelistEntry {
    ssid: String,
    bssid: String,
}

/// Accepts optional `ssid` and `date` query parameters.
async fn get_whitelist(Query(params): Query<HashMap<String, String>>) -> impl IntoResponse {
    let database = get_collection().await.expect("Failed to connect to DB");
    let my_coll: Collection<WhitelistedNetwork> = database.collection("Whitelist");

    // Extract optional params
    let ssid_query = params.get("ssid");
    let date_query = params.get("date"); // Expected format: YYYY-MM-DD

    let mut filter = doc! {};

    // SSID case-insensitive partial match
    if let Some(ssid) = ssid_query {
        filter.insert(
            "ssid",
            doc! {
                "$regex": ssid,
                "$options": "i"  // Case-insensitive
            },
        );
    }

    // Timestamp exact date match (00:00 to 23:59)
    if let Some(date_str) = date_query {
        if let Ok(parsed_date) = chrono::NaiveDate::parse_from_str(date_str, "%Y-%m-%d") {
            let start = Utc.from_utc_datetime(&parsed_date.and_hms_opt(0, 0, 0).unwrap());
            let end = Utc.from_utc_datetime(&parsed_date.and_hms_opt(23, 59, 59).unwrap());

            filter.insert(
                "timestamp",
                doc! {
                    "$gte": DateTime::from_millis(start.timestamp_millis()),
                    "$lte": DateTime::from_millis(end.timestamp_millis()),
                },
            );
        }
    }

    let mut cursor = match my_coll.find(filter).await {
        Ok(cursor) => cursor,
        Err(err) => {
            let body = Json(serde_json::json!({ "error": err.to_string() }));
            return (StatusCode::INTERNAL_SERVER_ERROR, body).into_response();
        }
    };

    let mut results = Vec::new();
    while let Some(doc) = cursor.try_next().await.unwrap_or(None) {
        results.push(WhitelistedNetworkResponse {
            id: doc.id.to_hex(),
            ssid: doc.ssid,
            bssid: doc.bssid,
            timestamp: doc.timestamp,
        });
    }

    Json(results).into_response()
}

async fn delete_from_whitelist(Path(id): Path<String>) -> impl IntoResponse {
    let db = get_collection().await.expect("DB connection");
    let coll: Collection<WhitelistedNetwork> = db.collection("Whitelist");

    let obj_id = match ObjectId::parse_str(&id) {
        Ok(oid) => oid,
        Err(_) => {
            return (
                StatusCode::BAD_REQUEST,
                Json(serde_json::json!({"error": "Invalid id"})),
            )
                .into_response();
        }
    };

    match coll.delete_one(doc! { "_id": obj_id }).await {
        Ok(res) if res.deleted_count == 1 => (
            StatusCode::OK,
            Json(serde_json::json!({"status": "deleted"})),
        )
            .into_response(),
        Ok(_) => (
            StatusCode::NOT_FOUND,
            Json(serde_json::json!({"error": "Not found"})),
        )
            .into_response(),
        Err(e) => (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(serde_json::json!({"error": e.to_string()})),
        )
            .into_response(),
    }
}

async fn add_to_whitelist(
    JsonExtract(payload): JsonExtract<NewWhitelistEntry>,
) -> impl IntoResponse {
    let db = get_collection().await.expect("DB connection");
    let coll: Collection<Document> = db.collection("Whitelist");

    let new_doc = doc! {
        "ssid": payload.ssid,
        "bssid": payload.bssid,
        "timestamp": DateTime::now(),
    };

    match coll.insert_one(new_doc).await {
        Ok(_) => (
            StatusCode::CREATED,
            Json(serde_json::json!({"status": "added"})),
        )
            .into_response(),
        Err(e) => (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(serde_json::json!({"error": e.to_string()})),
        )
            .into_response(),
    }
}

#[tokio::main]
async fn main() {
    dotenv().ok();
    let cors = CorsLayer::very_permissive();

    let app = Router::new()
        .route("/blacklist", get(get_blacklist).post(add_to_blacklist))
        .route("/blacklist/{id}", delete(delete_from_blacklist))
        .route("/whitelist", get(get_whitelist).post(add_to_whitelist))
        .route("/whitelist/{id}", delete(delete_from_whitelist))
        .layer(cors);

    let listener = TcpListener::bind("localhost:3000").await.unwrap();

    axum::serve(listener, app.into_make_service())
        .await
        .unwrap();
}
