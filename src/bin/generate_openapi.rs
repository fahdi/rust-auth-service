use utoipa::OpenApi;

// Simplified OpenAPI spec focusing on models only for now
#[derive(OpenApi)]
#[openapi(
    components(
        schemas(
            rust_auth_service::models::user::CreateUserRequest,
            rust_auth_service::models::user::UpdateUserRequest,
            rust_auth_service::models::user::PasswordResetRequest,
            rust_auth_service::models::user::PasswordChangeRequest,
            rust_auth_service::models::user::EmailVerificationRequest,
            rust_auth_service::models::user::UserResponse,
            rust_auth_service::models::user::AuthResponse,
            rust_auth_service::models::user::UserRole,
            rust_auth_service::models::user::UserMetadata,
            rust_auth_service::utils::jwt::Claims,
        )
    ),
    tags(
        (name = "authentication", description = "User authentication and authorization"),
        (name = "users", description = "User profile management"),
        (name = "health", description = "Service health and monitoring"),
        (name = "system", description = "System metrics and statistics")
    ),
    info(
        title = "Rust Auth Service API",
        version = "0.1.0",
        description = "270x faster authentication service - production-ready out of the box",
        contact(
            name = "Rust Auth Service",
            url = "https://github.com/your-org/rust-auth-service",
            email = "your.email@example.com"
        ),
        license(
            name = "MIT",
            url = "https://opensource.org/licenses/MIT"
        )
    ),
    servers(
        (url = "http://localhost:8080", description = "Local development server"),
        (url = "https://api.example.com", description = "Production server")
    )
)]
struct TestApiDoc;

fn main() {
    println!("Generating OpenAPI specification...");
    
    let openapi = TestApiDoc::openapi();
    
    // Print the OpenAPI JSON
    match serde_json::to_string_pretty(&openapi) {
        Ok(json) => {
            println!("OpenAPI JSON generated successfully!");
            println!("Length: {} characters", json.len());
            println!("Endpoints found: {}", openapi.paths.paths.len());
            println!("\nAPI Title: {}", openapi.info.title);
            println!("API Version: {}", openapi.info.version);
            
            // Save to file
            std::fs::write("openapi.json", &json).expect("Failed to write OpenAPI JSON to file");
            println!("\nOpenAPI specification saved to openapi.json");
        }
        Err(e) => {
            eprintln!("Failed to serialize OpenAPI specification: {}", e);
            std::process::exit(1);
        }
    }
}