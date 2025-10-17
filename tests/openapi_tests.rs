use serde_json::Value;
use std::collections::HashSet;
use utoipa::OpenApi;

// Test OpenAPI specification
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_openapi_generation() {
        let openapi = TestApiDoc::openapi();
        let openapi_json = serde_json::to_value(&openapi).unwrap();

        // Test basic structure
        assert_eq!(openapi_json["openapi"], "3.0.3");
        assert_eq!(openapi_json["info"]["title"], "Rust Auth Service API");
        assert_eq!(openapi_json["info"]["version"], "0.1.0");

        // Test servers
        let servers = openapi_json["servers"].as_array().unwrap();
        assert_eq!(servers.len(), 2);
        assert_eq!(servers[0]["url"], "http://localhost:8080");
        assert_eq!(servers[1]["url"], "https://api.example.com");
    }

    #[test]
    fn test_openapi_components() {
        let openapi = TestApiDoc::openapi();

        // Ensure components exist
        assert!(openapi.components.is_some());
        let components = openapi.components.unwrap();

        // Test schemas by serializing to JSON and checking
        let json_value = serde_json::to_value(&components).unwrap();
        let schemas = json_value["schemas"].as_object().unwrap();
        assert!(!schemas.is_empty());

        // Expected schemas
        let expected_schemas = [
            "CreateUserRequest",
            "UpdateUserRequest",
            "PasswordResetRequest",
            "PasswordChangeRequest",
            "EmailVerificationRequest",
            "UserResponse",
            "AuthResponse",
            "UserRole",
            "UserMetadata",
            "Claims",
        ];

        for expected_schema in expected_schemas.iter() {
            assert!(
                schemas.contains_key(*expected_schema),
                "Missing schema: {}",
                expected_schema
            );
        }
    }

    #[test]
    fn test_openapi_tags() {
        let openapi = TestApiDoc::openapi();

        // Serialize to JSON to check tags
        let json_value = serde_json::to_value(&openapi).unwrap();
        let tags = json_value["tags"].as_array().unwrap();
        assert_eq!(tags.len(), 4);

        let tag_names: HashSet<String> = tags
            .iter()
            .map(|tag| tag["name"].as_str().unwrap().to_string())
            .collect();

        let expected_tags = ["authentication", "users", "health", "system"];
        for expected_tag in expected_tags.iter() {
            assert!(
                tag_names.contains(*expected_tag),
                "Missing tag: {}",
                expected_tag
            );
        }
    }

    #[test]
    fn test_openapi_serialization() {
        let openapi = TestApiDoc::openapi();

        // Test that it can be serialized to JSON
        let json_result = serde_json::to_string_pretty(&openapi);
        assert!(json_result.is_ok());

        let json_string = json_result.unwrap();
        assert!(!json_string.is_empty());
        assert!(json_string.len() > 1000); // Should be substantial

        // Test that it can be parsed back
        let parsed_result: Result<Value, _> = serde_json::from_str(&json_string);
        assert!(parsed_result.is_ok());

        let parsed_json = parsed_result.unwrap();
        assert_eq!(parsed_json["openapi"], "3.0.3");
        assert_eq!(parsed_json["info"]["title"], "Rust Auth Service API");
    }

    #[test]
    fn test_user_request_schema() {
        let openapi = TestApiDoc::openapi();
        let openapi_json = serde_json::to_value(&openapi).unwrap();
        let schemas = openapi_json["components"]["schemas"].as_object().unwrap();

        // Test CreateUserRequest schema
        let schema_json = &schemas["CreateUserRequest"];

        // Should have required fields
        let required = schema_json["required"].as_array().unwrap();
        let required_fields: HashSet<String> = required
            .iter()
            .map(|v| v.as_str().unwrap().to_string())
            .collect();

        assert!(required_fields.contains("email"));
        assert!(required_fields.contains("password"));
        assert!(required_fields.contains("first_name"));
        assert!(required_fields.contains("last_name"));

        // Should have properties
        let properties = schema_json["properties"].as_object().unwrap();
        assert!(properties.contains_key("email"));
        assert!(properties.contains_key("password"));
        assert!(properties.contains_key("first_name"));
        assert!(properties.contains_key("last_name"));
        assert!(properties.contains_key("role"));
        assert!(properties.contains_key("metadata"));
    }

    #[test]
    fn test_auth_response_schema() {
        let openapi = TestApiDoc::openapi();
        let openapi_json = serde_json::to_value(&openapi).unwrap();
        let schemas = openapi_json["components"]["schemas"].as_object().unwrap();

        // Test AuthResponse schema
        let schema_json = &schemas["AuthResponse"];

        // Should have required fields
        let required = schema_json["required"].as_array().unwrap();
        let required_fields: HashSet<String> = required
            .iter()
            .map(|v| v.as_str().unwrap().to_string())
            .collect();

        assert!(required_fields.contains("user"));
        assert!(required_fields.contains("access_token"));
        assert!(required_fields.contains("refresh_token"));
        assert!(required_fields.contains("expires_in"));

        // Should have properties
        let properties = schema_json["properties"].as_object().unwrap();
        assert!(properties.contains_key("user"));
        assert!(properties.contains_key("access_token"));
        assert!(properties.contains_key("refresh_token"));
        assert!(properties.contains_key("expires_in"));

        // Check types
        assert_eq!(properties["access_token"]["type"], "string");
        assert_eq!(properties["refresh_token"]["type"], "string");
        assert_eq!(properties["expires_in"]["type"], "integer");
    }

    #[test]
    fn test_jwt_claims_schema() {
        let openapi = TestApiDoc::openapi();
        let openapi_json = serde_json::to_value(&openapi).unwrap();
        let schemas = openapi_json["components"]["schemas"].as_object().unwrap();

        // Test Claims schema
        let schema_json = &schemas["Claims"];

        // Should have required JWT fields
        let required = schema_json["required"].as_array().unwrap();
        let required_fields: HashSet<String> = required
            .iter()
            .map(|v| v.as_str().unwrap().to_string())
            .collect();

        assert!(required_fields.contains("sub"));
        assert!(required_fields.contains("email"));
        assert!(required_fields.contains("role"));
        assert!(required_fields.contains("exp"));
        assert!(required_fields.contains("iat"));
        assert!(required_fields.contains("jti"));
        assert!(required_fields.contains("token_type"));

        // Should have properties
        let properties = schema_json["properties"].as_object().unwrap();
        assert!(properties.contains_key("sub"));
        assert!(properties.contains_key("email"));
        assert!(properties.contains_key("role"));
        assert!(properties.contains_key("exp"));
        assert!(properties.contains_key("iat"));
        assert!(properties.contains_key("jti"));
        assert!(properties.contains_key("token_type"));
    }

    #[test]
    fn test_openapi_contact_and_license() {
        let openapi = TestApiDoc::openapi();
        let openapi_json = serde_json::to_value(&openapi).unwrap();

        // Test contact information
        let contact = &openapi_json["info"]["contact"];
        assert_eq!(contact["name"], "Rust Auth Service");
        assert_eq!(
            contact["url"],
            "https://github.com/your-org/rust-auth-service"
        );
        assert_eq!(contact["email"], "your.email@example.com");

        // Test license information
        let license = &openapi_json["info"]["license"];
        assert_eq!(license["name"], "MIT");
        assert_eq!(license["url"], "https://opensource.org/licenses/MIT");
    }
}
