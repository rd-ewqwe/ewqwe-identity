# **Rust Open Core Architecture: Cargo \+ crates.io Strategy**

This document serves as the official architectural reference for maintaining a multi-crate Rust project using the Open Core business model. It outlines the repository structure, subsystem abstraction patterns, developer workflows, and publishing requirements.

## **1\. High-Level Architecture**

The architecture relies on strict physical separation between open-source and proprietary code, leveraging **Cargo** and **crates.io** for dependency management.

| Attribute | Public Repository (my-project-public) | Enterprise Repository (my-project-enterprise) |
| :---- | :---- | :---- |
| **License** | BSL-1.1 | Proprietary / Closed Source |
| **Contents** | Core traits, standard implementations, routing engine, default CLI binary. | OIDC auth, OpenTelemetry, advanced storage (S3), enterprise CLI binary, deployment scripts. |
| **Distribution** | Published and fetched via crates.io | Internal / Private distribution |

## **2\. Subsystem Abstractions**

To ensure the public code remains completely isolated from enterprise secrets, distinct abstraction strategies are required for different architectural domains.

### **2.1 Storage: Dynamic Dispatch**

Storage backends are abstracted using Rust's async traits and dynamic dispatch. The public library relies on the trait, while the enterprise binary injects the proprietary implementation.

// In my-project-core (Public Library)  
use std::sync::Arc;

pub trait StorageBackend: Send \+ Sync {  
    async fn get\_user(\&self, id: \&str) \-\> Result\<User, StorageError\>;  
}

// Passed into Actix Web application state  
\#\[derive(Clone)\]  
pub struct AppState {  
    pub storage: Arc\<dyn StorageBackend\>,   
}

### **2.2 Authentication: ServiceConfig Pattern**

Actix Web's strongly-typed middleware system makes dynamic trait injection difficult for middlewares. Instead, the public server library exposes a modular route configuration function, leaving the final App and middleware construction exclusively to the binary crates.

// In enterprise-cli (Private Binary)  
use actix\_web::{App, HttpServer};  
use my\_project\_server::routes::configure\_routes;  
use enterprise\_auth::OidcMiddleware;

\#\[actix\_web::main\]  
async fn main() \-\> std::io::Result\<()\> {  
    HttpServer::new(move || {  
        App::new()  
            .wrap(OidcMiddleware::new()) // Injects Enterprise Auth  
            .configure(configure\_routes) // Wires up Public Routes  
    })  
    .bind(("127.0.0.1", 8080))?  
    .run()  
    .await  
}

### **2.3 Telemetry: The Tracing Facade**

The public code depends purely on the tracing crate to emit events and spans, maintaining zero knowledge of collectors. The enterprise CLI handles initialization by registering a tracing-opentelemetry subscriber before starting the server, exporting the spans via OTLP to external observability tools.

## **3\. Developer Workflow: Local Bug Fixing**

To seamlessly test public code fixes within the enterprise repository without publishing intermediate versions, developers use Cargo's \[patch.crates-io\] capability.

1. Maintain local clones of both the public and enterprise repositories side-by-side.  
2. Add the patch block to the enterprise Cargo.toml to override the crates.io dependencies with local path dependencies (do not commit this block to the main branch).  
3. Implement the bug fix directly in the public repository folder.  
4. Run cargo run in the enterprise repository to instantly verify the fix.  
5. Commit the fix to the public repository, merge, and publish the new version.

\# At the bottom of my-project-enterprise/Cargo.toml  
\[dependencies\]  
my-project-core \= "1.2.0"  
my-project-server \= "1.2.0"

\# Uncomment for local development overrides:  
\# \[patch.crates-io\]  
\# my-project-core \= { path \= "../../my-project-public/crates/my-project-core" }  
\# my-project-server \= { path \= "../../my-project-public/crates/my-project-server" }

## **4\. Publishing sequence for crates.io**

When releasing updates, crates must be published in a strict topological order (bottom-up). A crate cannot be published unless its dependencies are already accessible on the crates.io index.

* **Step 1:** cargo publish \-p my-project-core  
* **Step 2:** Wait for index propagation.  
* **Step 3:** cargo publish \-p my-project-server (Depends on core).  
* **Step 4:** cargo publish \-p my-project-cli (Depends on server).

It is recommended to use automation tools like cargo-release to handle this process. Ensure the license is defined explicitly in every public Cargo.toml as license \= "BSL-1.1".