mod auth;
mod client;
mod config;
mod format;
mod schema;
mod skills;
mod token_store;
mod upload;
mod web_login;

use clap::{Parser, Subcommand};
use client::{ApiClient, HttpMethod, ListParams};
use config::Config;
use format::json_type_name;

/// The clap-aware counterpart of `client::HttpMethod` - carries the
/// `#[derive(clap::ValueEnum)]` that parses `klaay call`'s `--method`
/// argument, so `client.rs`'s `HttpMethod` (the type the HTTP client layer
/// actually works with) doesn't need to depend on `clap` itself. Converted
/// via `From` right where `Commands::Call` is handled.
#[derive(Clone, Copy, Debug, clap::ValueEnum)]
enum CliHttpMethod {
    Get,
    Post,
    Patch,
    Put,
    Delete,
}

impl From<CliHttpMethod> for HttpMethod {
    fn from(method: CliHttpMethod) -> Self {
        match method {
            CliHttpMethod::Get => HttpMethod::Get,
            CliHttpMethod::Post => HttpMethod::Post,
            CliHttpMethod::Patch => HttpMethod::Patch,
            CliHttpMethod::Put => HttpMethod::Put,
            CliHttpMethod::Delete => HttpMethod::Delete,
        }
    }
}

fn api_url_help() -> String {
    format!(
        "Override the API base URL (defaults to {}, or the KLAAY_API_URL env var if set).",
        config::DEFAULT_API_URL
    )
}

fn web_url_help() -> String {
    format!(
        "Override the web app URL the browser sign-in opens (defaults to {}, or the KLAAY_WEB_URL env var if set).",
        config::DEFAULT_WEB_URL
    )
}

#[derive(Parser)]
#[command(
    name = "klaay",
    about = "Command-line client for the Klaay API",
    version
)]
struct Cli {
    // `help = api_url_help()`, not a `///` doc comment with the URL spelled
    // out again - `concat!` (the usual way to interpolate a `const` into a
    // doc comment at compile time) only accepts literals, not a named
    // `const`, so a doc comment here could only ever restate the default
    // literally, independent of `config::DEFAULT_API_URL` - exactly the
    // duplication this avoids. clap's derive macro evaluates `help` as a
    // runtime expression (confirmed empirically against this pinned clap
    // 4.6.1: a throwaway crate with `help = a_function_call()` produced the
    // function's return value as the rendered `--help` text), so this stays
    // in sync with the real default automatically.
    #[arg(long, global = true, help = api_url_help())]
    api_url: Option<String>,

    // Same runtime-help pattern as --api-url above, same reason.
    #[arg(long, global = true, help = web_url_help())]
    web_url: Option<String>,

    /// Allow --api-url to point at a non-loopback, non-HTTPS host, sending
    /// credentials/SSO tokens in plain text (also settable via
    /// KLAAY_ALLOW_INSECURE=1/true/yes). Off by default: without this, such
    /// a URL is a hard error rather than a warning a script might never
    /// surface.
    #[arg(long, global = true)]
    force_insecure: bool,

    #[command(subcommand)]
    command: Commands,
}

#[derive(Subcommand)]
enum Commands {
    /// Log in and store a token. With no flags, opens your browser at the
    /// Klaay login page (any sign-in method works there); --email switches
    /// to the email/password prompt.
    #[command(
        after_help = "Examples: klaay login  |  klaay login --email dev@customer.com  |  klaay login --with-token < token.txt"
    )]
    Login {
        #[arg(long)]
        email: Option<String>,
        /// Insecure: prefer the interactive prompt - a value passed here can
        /// end up in shell history, `ps` output, or system audit logs.
        #[arg(long, requires = "email")]
        password: Option<String>,
        /// Account id, if already known - skips the multi-account prompt
        /// (email/password flow only; the browser flow uses the account your
        /// web session selects).
        #[arg(long, requires = "email")]
        account: Option<String>,
        /// Read an already-minted token from stdin instead of signing in -
        /// for SSH sessions and CI, where the browser flow can't reach this
        /// machine.
        #[arg(long, conflicts_with_all = ["email", "password", "account"])]
        with_token: bool,
    },
    /// Clear the stored token.
    Logout,
    /// Show who you're logged in as (calls the real GET /me endpoint).
    Whoami,
    /// List every resource type the API exposes, derived from GET /openapi.
    #[command(after_help = "Example: klaay resources")]
    Resources {
        /// Force a re-fetch instead of using the cached spec.
        #[arg(long)]
        refresh: bool,
    },
    /// Show filters/sortable fields/relationships/attributes for one resource.
    #[command(after_help = "Example: klaay describe selected_controls")]
    Describe {
        resource: String,
        #[arg(long)]
        refresh: bool,
    },
    /// List a resource collection.
    #[command(
        after_help = "Example: klaay list selected_controls --filter state_include=ready --filter state_include=implemented --sort=-name --include owners --page-size 5"
    )]
    List {
        resource: String,
        /// key=value; repeat the same key for a multi-value (array) filter.
        #[arg(long = "filter")]
        filters: Vec<String>,
        #[arg(long)]
        sort: Option<String>,
        #[arg(long)]
        include: Option<String>,
        /// type:field1,field2 (sparse fieldset for that resource type).
        #[arg(long)]
        fields: Option<String>,
        #[arg(long = "page-number")]
        page_number: Option<u32>,
        #[arg(long = "page-size")]
        page_size: Option<u32>,
    },
    /// Get a single resource by id.
    #[command(after_help = "Example: klaay get selected_controls 101 --include owners")]
    Get {
        resource: String,
        id: String,
        #[arg(long)]
        include: Option<String>,
        #[arg(long)]
        fields: Option<String>,
    },
    /// Create a resource. --data is a JSON:API `data` fragment (attributes/relationships).
    #[command(
        after_help = "Example: klaay create collected_evidences --data '{\"attributes\":{\"summary\":\"Q3 review\"}}' --file files=./evidence.png"
    )]
    Create {
        resource: String,
        #[arg(long)]
        data: Option<String>,
        /// relationship=path, repeatable; drives the ActiveStorage direct-upload flow.
        #[arg(long = "file")]
        files: Vec<String>,
    },
    /// Update a resource. --data is a JSON:API `data` fragment (attributes/relationships).
    #[command(
        after_help = "Example: klaay update selected_controls 101 --data '{\"attributes\":{\"state\":\"implemented\"}}'"
    )]
    Update {
        resource: String,
        id: String,
        #[arg(long)]
        data: Option<String>,
        #[arg(long = "file")]
        files: Vec<String>,
    },
    /// Delete a resource.
    Delete { resource: String, id: String },
    /// Low-level escape hatch for documented endpoints that aren't a standard
    /// list/get(resource,id) shape (GET /me, /selected_risk_scenarios/stats, etc).
    #[command(after_help = "Example: klaay call GET /selected_risk_scenarios/stats")]
    Call {
        /// Case-insensitive (GET/get/Get all work) to match the uppercase
        /// HTTP-method convention used throughout this CLI's own docs.
        #[arg(value_enum, ignore_case = true)]
        method: CliHttpMethod,
        path: String,
        #[arg(long)]
        data: Option<String>,
    },
    /// Readiness snapshot - the same numbers as the "Road to Readiness" widget (admin-only).
    Status {
        /// Print the raw /compliance_stats response instead of a formatted summary.
        #[arg(long)]
        json: bool,
    },
}

/// Parses a `--data`/`--filter` JSON argument or exits with a clear message -
/// an agent-supplied malformed JSON fragment shouldn't produce a raw panic.
fn parse_json_arg(raw: &str, flag: &str) -> serde_json::Value {
    serde_json::from_str(raw).unwrap_or_else(|e| {
        eprintln!("{flag} is not valid JSON: {e}");
        std::process::exit(1);
    })
}

/// `set_type`/the `id` assignment in `Create`/`Update` both index into `body`
/// with a string key, which for a non-Object `serde_json::Value` (e.g.
/// `--data '[1,2,3]'`) silently *replaces* the whole value with a fresh
/// Object instead of erroring - discarding whatever the user actually passed
/// in `--data`. Guard against that shape up front instead.
fn require_data_is_object(body: &serde_json::Value) {
    if !body.is_object() {
        eprintln!(
            "--data must be a JSON object (got a {})",
            json_type_name(body)
        );
        std::process::exit(1);
    }
}

/// Parses repeated `key=value` flag values, exiting with a clear message on
/// any entry missing the `=` separator or with an empty key instead of
/// silently dropping it. Shared by `parse_filter_flags`/`parse_file_flags`
/// below - only the empty-*value* check differs between the two, so it's
/// not part of this common helper (see each wrapper for why).
fn parse_key_value_flags(values: &[String], flag: &str) -> Vec<(String, String)> {
    values
        .iter()
        .map(|v| {
            let (k, val) = v.split_once('=').unwrap_or_else(|| {
                eprintln!("Invalid {flag} value (expected key=value): {v}");
                std::process::exit(1);
            });
            if k.is_empty() {
                eprintln!("Invalid {flag} value (key must not be empty): {v}");
                std::process::exit(1);
            }
            (k.to_string(), val.to_string())
        })
        .collect()
}

/// `--filter key=value` - an empty value is left as-is (not rejected the way
/// `parse_file_flags` rejects one) since some server-side scopes accept
/// `filter[key]=` to mean "match records where this field is blank/empty",
/// a legitimate query this crate shouldn't preclude just because it looks
/// like a typo.
fn parse_filter_flags(values: &[String]) -> Vec<(String, String)> {
    parse_key_value_flags(values, "--filter")
}

/// `--file relationship=path` - an empty value is rejected here (unlike
/// `parse_filter_flags`) because an empty path string is never useful: it
/// reaches `upload::direct_upload` where `Path::new("")` silently resolves
/// to the current working directory, producing a confusing downstream
/// error instead of a clear one here.
fn parse_file_flags(values: &[String]) -> Vec<(String, String)> {
    parse_key_value_flags(values, "--file")
        .into_iter()
        .map(|(k, v)| {
            if v.is_empty() {
                eprintln!("Invalid --file value (value must not be empty): {k}=");
                std::process::exit(1);
            }
            (k, v)
        })
        .collect()
}

/// Parses `--fields type:field1,field2`, exiting with a clear message if the
/// `:` separator is missing instead of silently dropping the sparse-fieldset
/// constraint (which would otherwise just return every field with no
/// indication the flag was ignored).
/// Returns owned `String`s rather than slices borrowed from `fields` - the
/// `List` call site already converted the borrowed form to owned right
/// after calling this, but `Get` passed the borrowed slices straight through
/// to `client.get_one`, tying their lifetime to `fields`'s scope in that
/// match arm by coincidence rather than by any guarantee. Owning the strings
/// here means both call sites (and any future one) are safe regardless of
/// how they're structured.
fn parse_fields_arg(fields: Option<&str>) -> Option<(String, String)> {
    fields.map(|f| {
        let (t, v) = f.split_once(':').unwrap_or_else(|| {
            eprintln!("Invalid --fields value (expected type:field1,field2): {f}");
            std::process::exit(1);
        });
        // `split_once` only guarantees the `:` separator itself is present -
        // not that either side is non-empty. Without this, ":field1" would
        // silently send `fields[]=field1` (an empty resource-type key the
        // server would never match) and "type:" would silently send an empty
        // `fields[type]=` value, in both cases producing either a no-op or a
        // nonsensical sparse-fieldset query parameter with no indication the
        // flag was effectively ignored - the same failure mode this
        // function's own doc comment already describes for a missing `:`.
        if t.is_empty() || v.is_empty() {
            eprintln!("Invalid --fields value (expected type:field1,field2): {f}");
            std::process::exit(1);
        }
        (t.to_string(), v.to_string())
    })
}

fn main() {
    let cli = Cli::parse();
    let config =
        Config::resolve(cli.api_url, cli.web_url, cli.force_insecure).unwrap_or_else(|e| {
            eprintln!("Error: {e}");
            std::process::exit(1);
        });

    match cli.command {
        Commands::Login {
            email,
            password,
            account,
            with_token,
        } => {
            // Wrapped immediately at the destructure site rather than left
            // as a plain `Option<String>` until `auth::login` wraps it - this
            // protects the entire lifetime of the string's one heap
            // allocation (moves never clone the backing buffer), covering
            // the branch checks below too.
            let password = password.map(zeroize::Zeroizing::new);
            // Same reasoning as `password` above - the email address is PII.
            let email = email.map(zeroize::Zeroizing::new);
            if with_token {
                auth::login_with_stdin_token(&config);
            // No `|| password.is_some()` arm: clap's `requires = "email"`
            // on --password makes a password-without-email invocation a
            // parse error before this code runs.
            } else if email.is_some() {
                auth::login(&config, email, password, account);
            } else {
                // The default: borrow the web app's login page (every sign-in
                // method the deployment supports) via the server-side nonce
                // mailbox. clap's `requires`/`conflicts_with_all` rules above
                // guarantee `account` is None on this branch.
                web_login::login_via_browser(&config);
            }
        }
        Commands::Logout => auth::logout(&config),
        Commands::Whoami => auth::whoami(&config),
        Commands::Resources { refresh } => {
            let client = authenticated_client(&config);
            let spec = schema::fetch_spec(&client, refresh).unwrap_or_else(|e| exit_with_error(e));
            if let Err(e) = schema::list_resources(&spec) {
                exit_with_error(e);
            }
        }
        Commands::Describe { resource, refresh } => {
            let client = authenticated_client(&config);
            let spec = schema::fetch_spec(&client, refresh).unwrap_or_else(|e| exit_with_error(e));
            if let Err(e) = schema::describe(&spec, &resource) {
                exit_with_error(e);
            }
        }
        Commands::List {
            resource,
            filters,
            sort,
            include,
            fields,
            page_number,
            page_size,
        } => {
            let client = authenticated_client(&config);
            let filter_pairs = parse_filter_flags(&filters);
            let fields_pair = parse_fields_arg(fields.as_deref());
            let params = ListParams {
                filters: filter_pairs,
                sort,
                include,
                fields: fields_pair,
                page_number,
                page_size,
            };
            let response = client.list(&resource, &params);
            client::print_list_response(&response);
        }
        Commands::Get {
            resource,
            id,
            include,
            fields,
        } => {
            let client = authenticated_client(&config);
            let fields_pair = parse_fields_arg(fields.as_deref());
            let fields_pair = fields_pair.as_ref().map(|(t, v)| (t.as_str(), v.as_str()));
            let response = client.get_one(&resource, &id, include.as_deref(), fields_pair);
            client::print_response(&response);
        }
        Commands::Create {
            resource,
            data,
            files,
        } => {
            let client = authenticated_client(&config);
            // Validated here, before `set_type` inserts `resource` into the
            // body below - `client.create()` (called further down) also
            // validates it via the same `validate_path_segment`, but that
            // happens after this function has already built the full JSON
            // body containing it. Validating upfront makes the invariant
            // ("an invalid resource never even makes it into the body")
            // explicit at this call site rather than implicit in client.rs's
            // internal ordering, which a future refactor could otherwise
            // disturb without an obvious failure here.
            ApiClient::validate_path_segment(&resource, "resource");
            let mut body: serde_json::Value = data
                .as_deref()
                .map(|d| parse_json_arg(d, "--data"))
                .unwrap_or(serde_json::json!({}));
            require_data_is_object(&body);
            set_type(&mut body, &resource);
            // Unconditional, not gated on `!files.is_empty()` - a malformed
            // `--data '{"relationships": ...}'` shape is just as wrong
            // whether or not `--file` is also passed, and running this only
            // inside the upload branch meant `--data` alone (no `--file`)
            // silently forwarded a bad `relationships` value straight to
            // the API server, producing a confusing server-side error
            // instead of a clear client-side one.
            require_relationships_is_object_or_absent(&body);

            // Set from actual control flow (not `!files.is_empty()` up
            // front) so its correctness doesn't silently depend on
            // `build_relationships` always exiting rather than returning on
            // a partial failure - if that internal invariant ever changed,
            // a flag set upfront would carry the wrong value.
            let uploads_completed = if files.is_empty() {
                false
            } else {
                let file_pairs = parse_file_flags(&files);
                let relationships =
                    upload::build_relationships(&client, &file_pairs, config.force_insecure());
                merge_relationships(&mut body, relationships);
                true
            };

            let response = client.create(&resource, &body);
            warn_if_orphaned_upload(&response, uploads_completed);
            client::print_response(&response);
        }
        Commands::Update {
            resource,
            id,
            data,
            files,
        } => {
            let client = authenticated_client(&config);
            // Same reasoning as the Create arm above - validated before
            // `set_type` uses `resource`, not left to `client.update()`'s
            // internal ordering alone. `id` validated here too, not just
            // `resource` - `client.update()` would eventually reject an
            // invalid `id` on its own, but only after any `--file` uploads
            // below have already run, orphaning blobs in ActiveStorage for
            // exactly the reason the early `resource` check exists.
            ApiClient::validate_path_segment(&resource, "resource");
            ApiClient::validate_path_segment(&id, "id");
            let mut body: serde_json::Value = data
                .as_deref()
                .map(|d| parse_json_arg(d, "--data"))
                .unwrap_or(serde_json::json!({}));
            require_data_is_object(&body);
            set_type(&mut body, &resource);
            // Same reasoning as the Create arm above - unconditional, not
            // gated on `!files.is_empty()`.
            require_relationships_is_object_or_absent(&body);
            // A hard error (matching `set_type`'s handling of a conflicting
            // `type`), not a silent overwrite, when `--data` already
            // specifies an `id` that disagrees with the command-line `id`
            // argument - otherwise an agent/script passing both would have
            // the `--data` value silently discarded with no indication which
            // one actually reached the server.
            if let Some(existing_id) = body.get("id") {
                // `null` specifically means "no id override" in JSON:API
                // convention (e.g. a template for a new resource), not a
                // genuinely conflicting value - treated the same as the key
                // being absent (the command-line `id` still takes effect),
                // rather than grouped with a truly wrong type (a number,
                // bool, array, object) under the generic non-string error
                // below.
                if existing_id.is_null() {
                    // Still just a warning, not an error - the command-line
                    // id is well-defined and takes effect regardless. But a
                    // template built from a fetched resource (e.g. one whose
                    // "id" was blanked out before reuse) silently overwriting
                    // an explicit `null` is exactly the kind of thing a
                    // template-driven caller could miss without this, since
                    // it looks identical to the key being absent entirely
                    // from the printed request.
                    eprintln!(
                        "Warning: --data 'id' is null - using the command-line id \"{id}\" instead."
                    );
                } else {
                    match existing_id.as_str() {
                        // Already matches - nothing to do.
                        Some(s) if s == id.as_str() => {}
                        Some(s) => {
                            eprintln!(
                                "Error: --data specified id {s:?}, which conflicts with the command-line id \"{id}\"."
                            );
                            eprintln!(
                                "Remove the \"id\" key from --data, or make it match \"{id}\"."
                            );
                            std::process::exit(1);
                        }
                        // A non-string, non-null id (e.g. a JSON number) is
                        // never a match regardless of its value - `.as_str()`
                        // returning `None` for every non-string `Value` would
                        // otherwise make this report a "conflict" even when
                        // the number and the command-line id are the same
                        // account/resource, misleadingly implying two
                        // different ids were given rather than the real
                        // problem (JSON:API ids must be strings).
                        None => {
                            eprintln!(
                                "Error: --data 'id' was not a string (got a {}) - JSON:API resource ids must be strings.",
                                json_type_name(existing_id)
                            );
                            std::process::exit(1);
                        }
                    }
                }
            }
            // Clones rather than moving `id` into `body` and borrowing it
            // back out afterward - that round-trip ties `id`'s lifetime to
            // `body` and relies on `merge_relationships` only ever touching
            // the "relationships" key, an implicit invariant a future change
            // could silently break. `id` is a small resource identifier, not
            // a secret, so the clone's cost is negligible next to that
            // fragility.
            body["id"] = serde_json::Value::String(id.clone());

            let uploads_completed = if files.is_empty() {
                false
            } else {
                let file_pairs = parse_file_flags(&files);
                let relationships =
                    upload::build_relationships(&client, &file_pairs, config.force_insecure());
                merge_relationships(&mut body, relationships);
                true
            };

            let response = client.update(&resource, &id, &body);
            warn_if_orphaned_upload(&response, uploads_completed);
            client::print_response(&response);
        }
        Commands::Delete { resource, id } => {
            let client = authenticated_client(&config);
            let response = client.delete_one(&resource, &id);
            if response.is_success() {
                println!("Deleted {resource}/{id}");
            } else {
                client::print_response(&response);
            }
        }
        Commands::Call { method, path, data } => {
            let method: HttpMethod = method.into();
            let client = authenticated_client(&config);
            let body: Option<serde_json::Value> =
                data.as_deref().map(|d| parse_json_arg(d, "--data"));
            // Mirrors Create/Update's guard: a non-object --data value sent
            // to a mutating method would otherwise reach the server with no
            // client-side warning, and any resource-shaped downstream
            // handling of it would hit the same silent-clobber issue
            // require_data_is_object exists to catch for Create/Update.
            if matches!(
                method,
                HttpMethod::Post | HttpMethod::Patch | HttpMethod::Put
            ) {
                if let Some(body) = &body {
                    require_data_is_object(body);
                }
            } else if body.is_some() {
                // GET/DELETE never forward `data` to the request at all (see
                // client::call) - a hard error, not a warning-and-continue,
                // since passing --data here is almost certainly a mistake
                // (a typo'd method, a scripting error) rather than
                // intentional, and continuing would silently drop the
                // payload while still returning a normal-looking response -
                // a script capturing only stdout would never see the
                // warning on stderr at all.
                eprintln!(
                    "Error: --data is not sent for {} requests (it has no request body).",
                    method.as_str()
                );
                std::process::exit(1);
            }
            let response = client.call(method, &path, body.as_ref());
            client::print_response(&response);
        }
        Commands::Status { json } => {
            let client = authenticated_client(&config);
            client::print_status(&client, json);
        }
    }
}

/// Builds an authenticated `ApiClient` from the stored token, requiring one
/// exist first - shared by every command that needs the live API, rather
/// than each of the 9 call sites duplicating `auth::require_login` +
/// `ApiClient::new(config.api_url().to_string(), Some(stored.token...))`
/// (and each needing to remember the exact `StoredToken`/`ApiClient::new`
/// field shapes if either ever changes).
fn authenticated_client(config: &Config) -> ApiClient {
    let stored = auth::require_login(config);
    // Clones the already-`Zeroizing` token rather than moving it out -
    // `StoredToken` now derives `ZeroizeOnDrop`, and a type with a `Drop`
    // impl can't have a field partially moved out of it. The clone is still
    // a `Zeroizing<String>`, so no protection is lost, just one extra
    // (zeroized) allocation - `stored` itself is then dropped normally here,
    // zeroizing its own copy of the token too.
    ApiClient::new(config.api_url().to_string(), Some(stored.token.clone()))
}

/// Sets `data.type`, erroring rather than silently overwriting if `--data`
/// already specified a (presumably mismatched) type of its own. Callers are
/// expected to have already checked `require_data_is_object`, but this
/// re-asserts that invariant itself rather than trusting call order - a
/// non-object `body` here would otherwise silently replace the whole value
/// via serde_json's `IndexMut`, the exact bug `require_data_is_object` exists
/// to prevent.
fn set_type(body: &mut serde_json::Value, resource: &str) {
    // A programmer invariant, not a user-correctable error - both real call
    // sites already call `require_data_is_object` immediately before this, so
    // a non-object `body` here can only mean a future call site skipped that
    // check, not something a CLI user did. A single `assert!` (not a
    // `debug_assert!` + separate release-mode `if` fallback, as an earlier
    // version had) - that split invited a future maintainer to remove the
    // `if` block believing `debug_assert!` alone already covered it, silently
    // re-exposing `IndexMut`'s replace-the-whole-value behavior in release
    // builds. `assert!` fires in both debug and release builds with a clear
    // panic and backtrace, so there's only one path to keep in sync.
    assert!(
        body.is_object(),
        "set_type called on a non-object body - caller must call require_data_is_object first"
    );
    if let Some(existing) = body.get("type") {
        // `let ... else`, not a `match` on `existing.as_str()` with a `None`
        // arm nested inside this `if let Some(existing)` - a nested `None`
        // reads, at a glance, like it might be handling "the 'type' key is
        // absent" (the outer `if let`'s own negative case), when it's
        // actually "the key is present but its value isn't a string" (e.g.
        // `42` or `null`). Spelling it out as its own named binding avoids
        // that ambiguity for a future reader.
        let Some(existing_type) = existing.as_str() else {
            eprintln!(
                "Error: --data 'type' was not a string (got a {}) - cannot set resource type.",
                json_type_name(existing)
            );
            std::process::exit(1);
        };
        // Already correct - returns explicitly instead of falling through
        // to the unconditional assignment below, which would otherwise
        // silently re-overwrite an already-confirmed-matching value with
        // itself. Harmless today, but makes the "nothing to do here" case
        // self-contained rather than relying on the reassignment being a
        // no-op.
        if existing_type == resource {
            return;
        }
        // A hard error, not a warning-and-override - the same reasoning as
        // `merge_relationships`'s non-object-relationships case: a script or
        // agent capturing only stdout would never see a stderr warning, so
        // their explicit --data type would be silently discarded with no
        // way to know it happened.
        eprintln!(
            "Error: --data specified type \"{existing_type}\", which conflicts with resource \"{resource}\"."
        );
        eprintln!("Remove the \"type\" key from --data, or make it match \"{resource}\".");
        std::process::exit(1);
    }
    body["type"] = serde_json::Value::String(resource.to_string());
}

/// Checked by `Create`/`Update` before any `--file` upload starts - catches
/// the same shape problem `merge_relationships`'s `Some(existing)` arm below
/// does, just early enough that a malformed `--data 'relationships'` field
/// is rejected before any blob has been uploaded, rather than after every
/// one has. `merge_relationships`'s own exit paths also warn now (see
/// `note_orphaned_uploads`), so this early check is purely about
/// failing before the uploads even start, not about being the only place
/// that warns.
fn require_relationships_is_object_or_absent(body: &serde_json::Value) {
    match body.get("relationships") {
        None | Some(serde_json::Value::Object(_)) => {}
        Some(existing) => {
            eprintln!(
                "Error: --data 'relationships' was not a JSON object (got a {}) - cannot merge uploaded file relationships.",
                json_type_name(existing)
            );
            eprintln!(
                "Fix the --data 'relationships' field to be a JSON object, or omit it and let --file build it."
            );
            std::process::exit(1);
        }
    }
}

/// Both call sites only invoke `merge_relationships` when `--file` was
/// passed, and only after `upload::build_relationships` has already
/// returned - which it only ever does once every upload in the batch has
/// actually succeeded (a partial failure exits from inside that function
/// instead). So every exit path below runs strictly after the real uploads
/// already completed: printed right before each `process::exit(1)` so a
/// relationships-shape problem discovered here doesn't leave the user
/// thinking nothing happened yet, when in fact the blob(s) are already
/// sitting in ActiveStorage, orphaned, with no create/update call ever
/// reaching the server to attach them.
fn note_orphaned_uploads() {
    eprintln!(
        "Note: the file upload(s) above already completed before this failure - the uploaded blob(s) exist in ActiveStorage but aren't attached to anything."
    );
}

fn merge_relationships(body: &mut serde_json::Value, relationships: serde_json::Value) {
    // A hard error, not a silent no-op (even for `Value::Null`, which an
    // earlier version of this function specifically special-cased to return
    // quietly) - `build_relationships` always returns a `Value::Object`
    // today, so this path is unreachable in practice, but a silent return
    // here is a latent data-loss trap: by the time this runs,
    // `uploads_completed` is already `true`, so every uploaded file's
    // `signed_id` would be dropped with no warning and no non-zero exit,
    // orphaning the blob with nothing to indicate it happened.
    let serde_json::Value::Object(new_rels) = relationships else {
        // Deliberately don't print `relationships` itself - on the upload
        // path it can carry ActiveStorage signed_id values, which shouldn't
        // land in stderr/CI logs/shell history.
        eprintln!(
            "Internal error: uploaded relationships were not a JSON object (got a {}) - file relationship(s) were not attached.",
            json_type_name(&relationships)
        );
        note_orphaned_uploads();
        std::process::exit(1);
    };
    match body.get_mut("relationships") {
        Some(serde_json::Value::Object(map)) => {
            for (k, v) in new_rels {
                // `entry()`, not a `contains_key` check followed by a
                // separate `insert` - the two-call form looks up `k` in the
                // map twice in the common (non-conflicting) case; `entry()`
                // does the single lookup this map access actually needs.
                // A hard error on `Occupied` (matching `set_type`'s handling
                // of a conflicting `type`), not a silent overwrite - letting
                // `insert` discard the old value would silently drop an
                // explicit `--data` relationship that happens to share a
                // name with a `--file <relationship>=<path>` flag, with no
                // indication to the user that their `--data` value was
                // never actually sent.
                match map.entry(k) {
                    serde_json::map::Entry::Occupied(entry) => {
                        let k = entry.key();
                        eprintln!(
                            "Error: --data 'relationships' already specifies \"{k}\", which conflicts with --file {k}=<path>."
                        );
                        eprintln!(
                            "Remove one of them - both can't apply to the same relationship."
                        );
                        note_orphaned_uploads();
                        std::process::exit(1);
                    }
                    serde_json::map::Entry::Vacant(entry) => {
                        entry.insert(v);
                    }
                }
            }
        }
        Some(existing) => {
            eprintln!(
                "Error: --data 'relationships' was not a JSON object (got a {}) - cannot merge uploaded file relationships.",
                json_type_name(existing)
            );
            eprintln!(
                "Fix the --data 'relationships' field to be a JSON object, or omit it and let --file build it."
            );
            note_orphaned_uploads();
            std::process::exit(1);
        }
        None => {
            body["relationships"] = serde_json::Value::Object(new_rels);
        }
    }
}

/// If `--file` upload(s) completed (see `uploads_completed` -
/// `build_relationships` only returns normally once every one has actually
/// finished; it always `process::exit(1)`s on a partial failure instead of
/// returning) but the subsequent create/update then fails, those blobs are
/// already stored and orphaned - the failed resource never got attached to
/// them, and there's no cleanup/rollback path. Says so explicitly so the
/// user isn't confused about what actually happened, rather than just
/// seeing an ordinary-looking API error. A failure *during* the upload
/// batch itself (e.g. file 2 of 3) is handled separately, inside
/// `upload::direct_upload`, which is the only place that knows how many
/// earlier files in the same batch already succeeded.
fn warn_if_orphaned_upload(response: &client::ApiResponse, uploads_completed: bool) {
    if uploads_completed && !response.is_success() {
        note_orphaned_uploads();
    }
}

/// Prints a `schema::fetch_spec`/`schema::describe` error and exits - the
/// one place both of those functions' `Err` case is handled, now that
/// they return `Result` instead of exiting internally.
///
/// `impl std::fmt::Display`, not `String` - every call site today happens to
/// already own a `String` (both functions return `Result<_, String>`), but
/// requiring `String` specifically would force a hypothetical future caller
/// with a `&str` or another `Display` type to allocate just to satisfy this
/// signature, for no benefit - `eprintln!` only ever needs `Display`.
fn exit_with_error(message: impl std::fmt::Display) -> ! {
    eprintln!("{message}");
    std::process::exit(1);
}
