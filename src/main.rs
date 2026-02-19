use std::{net::SocketAddr, path::PathBuf, sync::Arc};

use axum::{
    Json, Router,
    extract::State,
    http::{HeaderMap, HeaderValue, StatusCode},
    response::IntoResponse,
    routing::post,
};
use base64::{Engine, prelude::BASE64_STANDARD};
use bpaf::Bpaf;
use sha1::{Digest, Sha1};
use tokio::{fs::OpenOptions, io::AsyncWriteExt};

#[derive(Clone, Debug, Bpaf)]
#[bpaf(options, version)]
/// Server for hili.
struct Args {
    /// File to save received data
    #[bpaf(positional("SAVE_FILE"))]
    output_file: PathBuf,

    /// Directory to same uploaded files
    #[bpaf(positional("UPLOAD_DIR"))]
    upload_dir: PathBuf,

    /// Port for the server
    #[bpaf(short, long, fallback(8888))]
    port: u16,

    /// Secret key to authenticate clients
    #[bpaf(short, long)]
    key: String,
}

#[derive(Clone)]
struct AppState {
    key: String,
    upload_dir: PathBuf,
    output_file: PathBuf,
}

async fn handle_post(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    Json(mut payload): Json<serde_json::Value>,
) -> impl IntoResponse {
    let auth_header = headers.get("Authentication").and_then(|h| h.to_str().ok());
    if auth_header != Some(&state.key) {
        return (StatusCode::UNAUTHORIZED, "unauthorized").into_response();
    }

    // Handle included file, if any
    if let Some(file_obj) = payload.get_mut("file").and_then(|v| v.as_object_mut())
        && let (Some(data_val), Some(type_val)) = (file_obj.get("data"), file_obj.get("type"))
        && let (Some(b64_str), Some(type_str)) = (data_val.as_str(), type_val.as_str())
        && let Ok(bytes) = BASE64_STANDARD.decode(b64_str)
    {
        // Create content hash
        let mut hasher = Sha1::new();
        hasher.update(&bytes);
        let hex_hash = format!("{:x}", hasher.finalize());

        // Get extension based on specified content type
        let ext = type_str.split('/').next_back().unwrap_or("bin");
        let fname = format!("{}.{}", hex_hash, ext);

        // Save file to disk
        let file_path = state.upload_dir.join(&fname);
        let _ = tokio::fs::write(file_path, bytes).await;

        // Remove original data, save only filename
        file_obj.remove("data");
        file_obj.insert("name".to_string(), serde_json::Value::String(fname));
    }

    if let Ok(mut json_str) = serde_json::to_string(&payload) {
        json_str.push('\n');
        if let Ok(mut file) = OpenOptions::new()
            .create(true)
            .append(true)
            .open(&state.output_file)
            .await
        {
            let _ = file.write_all(json_str.as_bytes()).await;
        }
    }

    let mut response = "ok".into_response();
    response
        .headers_mut()
        .insert("Access-Control-Allow-Origin", HeaderValue::from_static("*"));
    response
        .headers_mut()
        .insert("Content-Type", HeaderValue::from_static("text/html"));

    response
}

#[tokio::main]
async fn main() {
    let opts = args().run();
    let state = Arc::new(AppState {
        key: opts.key,
        upload_dir: opts.upload_dir,
        output_file: opts.output_file,
    });

    // Make sure the upload dir exists
    tokio::fs::create_dir_all(&state.upload_dir).await.unwrap();

    let app = Router::new()
        .route("/", post(handle_post))
        .with_state(state);

    let addr = SocketAddr::from(([127, 0, 0, 1], opts.port));
    println!("Listening on http://{}", addr);
    let listener = tokio::net::TcpListener::bind(addr).await.unwrap();
    axum::serve(listener, app).await.unwrap();
}
