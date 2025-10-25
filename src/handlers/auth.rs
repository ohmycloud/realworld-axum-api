use std::collections::HashMap;

use axum::{
    Json,
    extract::{Query, State},
    http::StatusCode,
};
use chrono::{Duration, Utc};
use serde_json::{Value, json};
use validator::Validate;

use crate::{
    auth::{
        jwt::generate_token,
        middleware::RequireAuth,
        password::{hash_password, verify_password},
        tokens::generate_refresh_token,
    },
    schemas::{
        LogoutRequest, LogoutResponse, RefreshTokenRequest, RefreshTokenResponse,
        auth_schemas::*,
        password_reset_schemas::{
            ForgotPasswordRequest, ForgotPasswordResponse, ResetPasswordRequest,
            ResetPasswordResponse,
        },
    },
    state::AppState,
    utils::generate_verification_token,
};

pub async fn register(
    State(state): State<AppState>,
    Json(payload): Json<RegisterUserRequest>,
) -> Result<Json<LoginResponse>, StatusCode> {
    // Validate input data
    payload
        .user
        .validate()
        .map_err(|_| StatusCode::BAD_REQUEST)?;

    // Check user if already exists
    if state
        .user_repository
        .find_by_email(&payload.user.email)
        .await
        .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?
        .is_some()
    {
        return Err(StatusCode::CONFLICT);
    }

    if state
        .user_repository
        .find_by_username(&payload.user.username)
        .await
        .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?
        .is_some()
    {
        return Err(StatusCode::CONFLICT);
    }

    // Hash the password
    let password_hash =
        hash_password(&payload.user.password).map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;

    // Create user in database
    let user = state
        .user_repository
        .create(&payload.user.username, &payload.user.email, &password_hash)
        .await
        .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;

    // Generate verification token
    let verification_token = generate_verification_token();
    let expires_at = Utc::now() + Duration::hours(24);

    // Save token to database
    state
        .email_verification_repository
        .create_token(user.id, &verification_token, expires_at)
        .await
        .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;

    // Send verification email
    state
        .email_service
        .send_verification_email(&user.email, &user.username, &verification_token)
        .await
        .map_err(|err| {
            eprintln!("Failed to send verification email: {}", err);
            StatusCode::INTERNAL_SERVER_ERROR
        })?;

    // Generate JWT access token (15 minutes)
    let jwt_secret = std::env::var("JWT_SECRET").map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;
    let access_token =
        generate_token(&user.id, &jwt_secret).map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;

    // Generate refresh token (UUID, no expiration)
    let refresh_token = generate_refresh_token();

    // Save refresh token to database
    state
        .refresh_token_repository
        .create_token(user.id, &refresh_token)
        .await
        .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;

    // Build response with BOTH tokens
    let response = LoginResponse {
        user: UserData::from_user(user),
        access_token,
        refresh_token,
    };

    Ok(Json(response))
}

pub async fn login(
    State(state): State<AppState>,
    Json(payload): Json<LoginUserRequest>,
) -> Result<Json<LoginResponse>, StatusCode> {
    // Validate input
    payload
        .user
        .validate()
        .map_err(|_| StatusCode::BAD_REQUEST)?;

    // Find user by email
    let user = state
        .user_repository
        .find_by_email(&payload.user.email)
        .await
        .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?
        .ok_or(StatusCode::UNAUTHORIZED)?;

    // Verify password
    let password_valid = verify_password(&payload.user.password, &user.password_hash)
        .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;

    if !password_valid {
        return Err(StatusCode::UNAUTHORIZED);
    }

    // Generate JWT access token (15 minutes)
    let jwt_secret = std::env::var("JWT_SECRET").map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;
    let access_token =
        generate_token(&user.id, &jwt_secret).map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;
    // Generate refresh token (UUID, no expiration)
    let refresh_token = generate_refresh_token();

    // Save refresh token to database
    state
        .refresh_token_repository
        .create_token(user.id, &refresh_token)
        .await
        .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;

    // Build response with BOTH tokens
    let response = LoginResponse {
        user: UserData::from_user(user),
        access_token,
        refresh_token,
    };

    Ok(Json(response))
}

pub async fn current_user(
    RequireAuth(user): RequireAuth,
) -> Result<Json<UserResponse>, StatusCode> {
    // Build response (no token needed - they already have one)
    let response = UserResponse {
        user: UserData::from_user(user),
    };

    Ok(Json(response))
}

pub async fn verify_email(
    State(state): State<AppState>,
    Query(params): Query<HashMap<String, String>>,
) -> Result<Json<Value>, StatusCode> {
    // Extract token from query params
    let token = params.get("token").ok_or(StatusCode::BAD_REQUEST)?;

    // Look up the token in database
    let verification_token = state
        .email_verification_repository
        .find_by_token(token)
        .await
        .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?
        .ok_or(StatusCode::NOT_FOUND)?;

    // Check if expired
    if verification_token.is_expired() {
        // Clean up expired token
        state
            .email_verification_repository
            .delete_token(token)
            .await
            .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;

        return Err(StatusCode::GONE);
    }

    // Mark user as verified
    state
        .email_verification_repository
        .verify_user_email(verification_token.user_id)
        .await
        .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;

    // Delete token (single-use)
    state
        .email_verification_repository
        .delete_token(token)
        .await
        .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;

    Ok(Json(json!({ "message": "Email verified successfully!" })))
}

pub async fn forgot_password(
    State(state): State<AppState>,
    Json(payload): Json<ForgotPasswordRequest>,
) -> Result<Json<ForgotPasswordResponse>, StatusCode> {
    // Validate email format
    payload.validate().map_err(|_| StatusCode::BAD_REQUEST)?;

    // Look up user by email
    let user = state
        .user_repository
        .find_by_email(&payload.email)
        .await
        .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;

    if user.is_none() {
        return Ok(Json(ForgotPasswordResponse {
            message: "If that email exists, a password reset link has been sent".to_string(),
        }));
    }

    let user = user.unwrap();

    // generate reset token
    let reset_token = generate_verification_token();
    let expires_at = Utc::now() + Duration::hours(1); // 1 hour expiration

    // Save token to database
    state
        .password_reset_repository
        .create_token(user.id, &reset_token, expires_at)
        .await
        .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;

    // Send reset email with token
    state
        .email_service
        .send_password_reset_email(&user.email, &user.username, &reset_token)
        .await
        .map_err(|e| {
            eprintln!("Failed to send password reset email: {}", e);
            StatusCode::INTERNAL_SERVER_ERROR
        })?;

    Ok(Json(ForgotPasswordResponse {
        message: "If that email exists, a password reset link has been sent".to_string(),
    }))
}

pub async fn reset_password(
    State(state): State<AppState>,
    Json(payload): Json<ResetPasswordRequest>,
) -> Result<Json<ResetPasswordResponse>, StatusCode> {
    // Validate new password
    payload.validate().map_err(|_| StatusCode::BAD_REQUEST)?;

    // Look up the token in database
    let reset_token = state
        .password_reset_repository
        .find_by_token(&payload.token)
        .await
        .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?
        .ok_or(StatusCode::NOT_FOUND)?;

    // Check if expired
    if reset_token.is_expired() {
        // Clean up expired token
        state
            .password_reset_repository
            .delete_token(&payload.token)
            .await
            .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;

        return Err(StatusCode::GONE);
    }

    // Hash new password
    let new_password_hash =
        hash_password(&payload.new_password).map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;

    // Update user password
    state
        .user_repository
        .update_password(reset_token.user_id, &new_password_hash)
        .await
        .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;

    // Delete all reset tokens for this user (invalidate any other pending requests)
    state
        .password_reset_repository
        .delete_all_user_tokens(reset_token.user_id)
        .await
        .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;

    Ok(Json(ResetPasswordResponse {
        message: "Password has been reset successfully. You can now login with your new password"
            .to_string(),
    }))
}

pub async fn refresh_token(
    State(state): State<AppState>,
    Json(payload): Json<RefreshTokenRequest>,
) -> Result<Json<RefreshTokenResponse>, StatusCode> {
    // lookup the refresh token in database
    let refresh_token = state
        .refresh_token_repository
        .find_by_token(&payload.refresh_token)
        .await
        .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?
        .ok_or(StatusCode::UNAUTHORIZED)?;

    // check if token has expired
    if refresh_token.is_expired() {
        // token is expired, delete it and reject
        let _ = state
            .refresh_token_repository
            .delete_token(&payload.refresh_token)
            .await;

        return Err(StatusCode::UNAUTHORIZED);
    }

    // reuse detection - Check if token was already used
    if refresh_token.is_used {
        // SECURITY BREACH DETECTED!
        // Someone is trying to use an old token
        // This means the token was likely stolen

        eprintln!("TOKEN REUSE DETECTED!");
        eprintln!("Token: {}", &payload.refresh_token);
        eprintln!("User ID: {}", refresh_token.user_id);
        eprintln!("Originally used at: {:?}", refresh_token.used_at);

        // Delete the token to prevent further reuse
        // Force them to login again
        state
            .refresh_token_repository
            .delete_all_user_tokens(refresh_token.user_id)
            .await
            .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;

        return Err(StatusCode::UNAUTHORIZED);
    }

    // mark the old token as used (consumed)
    state
        .refresh_token_repository
        .mark_token_as_used(&payload.refresh_token)
        .await
        .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;

    // generate new refresh token with rotation
    let new_refresh_token = generate_refresh_token();

    state
        .refresh_token_repository
        .create_token(refresh_token.user_id, &new_refresh_token)
        .await
        .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;

    // generate new access token
    let jwt_secret = std::env::var("JWT_SECRET").map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;
    let access_token = generate_token(&refresh_token.user_id, &jwt_secret)
        .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;

    // return both tokens
    Ok(Json(RefreshTokenResponse {
        access_token,
        refresh_token: new_refresh_token,
    }))
}

pub async fn logout(
    State(state): State<AppState>,
    Json(payload): Json<LogoutRequest>,
) -> Result<Json<LogoutResponse>, StatusCode> {
    // simply delete the refresh token from database
    state
        .refresh_token_repository
        .delete_token(&payload.refresh_token)
        .await
        .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;

    Ok(Json(LogoutResponse {
        message: "Logged out successfully".to_string(),
    }))
}
