use axum::{
    Json, Router,
    extract::{Json as JsonExtract, Path},
    http::StatusCode,
    response::IntoResponse,
    routing::{delete, get},
};
use futures::TryStreamExt;
use mongodb::Database;
use mongodb::bson::oid::ObjectId;
use mongodb::bson::{DateTime, Document};
use mongodb::{Client, Collection, bson::doc};
use serde::Serializer;
use serde::{Deserialize, Serialize};
use std::net::SocketAddr;
use tokio::net::TcpListener;
use tower_http::cors::CorsLayer;

fn serialize_datetime_as_iso_string<S>(date: &DateTime, serializer: S) -> Result<S::Ok, S::Error>
where
    S: Serializer,
{
    serializer.serialize_str(&date.to_rfc3339_string())
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
    let db_url = "mongodb+srv://imilay11:yiiWyudxZU2RIy0n@wisp-app.j5ndz0i.mongodb.net/?retryWrites=true&w=majority&appName=Wisp-App";
    let client = Client::with_uri_str(db_url)
        .await
        .expect("Failed to connect to MongoDB");
    let db = client.database("WISP-APP");
    Ok(db)
}

async fn get_blacklist() -> impl IntoResponse {
    let database = get_collection().await.expect("Failed to connect to DB");
    let my_coll: Collection<BlacklistedNetwork> = database.collection("Blacklist");

    let mut cursor = match my_coll.find(doc! {}).await {
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
async fn get_whitelist() -> impl IntoResponse {
    let database = get_collection().await.expect("Failed to connect to DB");
    let my_coll: Collection<WhitelistedNetwork> = database.collection("Whitelist");

    let mut cursor = match my_coll.find(doc! {}).await {
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
    let cors = CorsLayer::very_permissive();

    let app = Router::new()
        .route("/blacklist", get(get_blacklist).post(add_to_blacklist))
        .route("/blacklist/{id}", delete(delete_from_blacklist))
        .route("/whitelist", get(get_whitelist).post(add_to_whitelist))
        .route("/whitelist/{id}", delete(delete_from_whitelist))
        .layer(cors);

    let addr = SocketAddr::from(([0, 0, 0, 0], 3000));
    let listener = TcpListener::bind(addr).await.unwrap();

    println!("Listening on http://{}", addr);

    axum::serve(listener, app.into_make_service())
        .await
        .unwrap();
}
