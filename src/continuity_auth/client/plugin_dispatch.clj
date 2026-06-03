(ns continuity-auth.client.plugin-dispatch
  "Plugin-internal dispatcher for the `continuity-auth` binary. Routes one of:

      continuity-auth <auth-verb> [ARGS…]      → client.cli/run-auth
      continuity-auth admin <subcommand> […]   → admin.cli/run-admin
      continuity-auth --version | --help

  Invoked directly as `continuity-auth <args>` (via `bin/continuity-auth`,
  or any bbin/brew/manual install of the plugin binary) or transparently
  through the continuity-cli parent dispatcher as `continuity auth <args>`
  (the parent strips its own arg before spawning this binary).

  Designed to load under both babashka (the install-ergonomic surface)
  and the JVM (via `clojure -M -m continuity-auth.client.plugin-dispatch …`
  for development). Avoid any JVM-only require here.

  Predecessor: continuity-auth.client.dispatch (deleted with this change;
  the parent `continuity` dispatcher and the installer moved into the
  continuity-cli repo, where they belong)."
  (:require
   [clojure.edn :as edn]
   [clojure.java.io :as io]
   [clojure.string :as str]
   [continuity-auth.client.cli :as client-cli]))

(defn- read-config-version []
  (try
    (let [r (io/resource "config.edn")]
      (when r
        (-> r slurp edn/read-string :continuity-auth/version)))
    (catch Exception _ nil)))

(def ^:private fallback-version "0.1.0")

(defn- version-string []
  (or (read-config-version) fallback-version))

(def ^:private help-text
  (str
   "continuity-auth — cryptographic device-continuity client\n"
   "\n"
   "Invocation:\n"
   "  continuity-auth <subcommand> [ARGS…]    direct invocation\n"
   "  continuity auth <subcommand> [ARGS…]    via the continuity-cli parent\n"
   "\n"
   "Auth subcommands:\n"
   "  init                                    generate key + bootstrap identity\n"
   "  sign METHOD URL [BODY]                  emit signed envelope to stdout\n"
   "  curl ARGS… URL                          wrap curl, attach envelope header\n"
   "  wget ARGS… URL                          wrap wget, attach envelope header\n"
   "  show                                    print stored identity_ref + key info\n"
   "\n"
   "Admin subcommands (HMAC-authed; operator surface):\n"
   "  admin revoke-key <key-id-b64>           force-revoke a pubkey\n"
   "  admin config                            dump effective server config\n"
   "\n"
   "Env vars (auth):\n"
   "  CONTINUITY_AUTH_ENDPOINT  default http://localhost:8080\n"
   "  CONTINUITY_AUTH_HOME      default $XDG_CONFIG_HOME/continuity-auth\n"
   "  CONTINUITY_AUTH_HOST_ID   optional host_user_id field\n"
   "\n"
   "Env vars (admin):\n"
   "  CONTINUITY_AUTH_ENDPOINT, CONTINUITY_AUTH_ADMIN_KEY_ID, CONTINUITY_AUTH_ADMIN_SECRET_FILE\n"
   "  (or pass --server / --key-id / --secret-file)\n"))

(defn- subcommand-kw [s]
  (when s (keyword (str/replace s "_" "-"))))

;; The admin namespace is JVM-style today (uses `jsonista` indirectly via
;; the server.admin.hmac path it requires); a parallel bb-compatible
;; surface is provided by `continuity-auth.admin.cli`. Lazy-require to
;; defer loading until/unless admin is actually invoked.
(defn- run-admin [parsed]
  (try
    (require 'continuity-auth.admin.cli)
    (let [run (resolve 'continuity-auth.admin.cli/run-admin)]
      (if run
        (run parsed)
        (do (binding [*out* *err*]
              (println "admin namespace did not expose `run-admin` — internal error"))
            2)))
    (catch Throwable t
      (binding [*out* *err*]
        (println (str "Failed to load admin subsystem: " (.getMessage t))))
      2)))

(defn- parse-args [args]
  (let [[sub & rest] args]
    {:subcommand (subcommand-kw sub)
     :args       (vec rest)
     :opts       {}}))

(defn main
  "Entry point. Returns an integer exit code; does NOT call System/exit
  itself (callers — bin/continuity-auth, tests — make that decision)."
  [& argv]
  (let [args (vec argv)
        a0   (first args)]
    (cond
      (or (= "--help" a0) (= "-h" a0) (nil? a0))
      (do (println help-text) 0)

      (or (= "--version" a0) (= "-V" a0))
      (do (println (str "continuity-auth " (version-string))) 0)

      (= "admin" a0)
      (run-admin (parse-args (rest args)))

      :else
      (client-cli/run-auth (parse-args args)))))
