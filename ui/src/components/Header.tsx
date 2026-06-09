import { Activity, FileText, ShieldCheck, Lock, LogOut } from "lucide-react";
import { useState, useEffect, useRef } from "react";
import { FocusTrap } from "../a11y/FocusTrap";

interface HeaderProps {
  error: string;
}

export function Header({ error }: HeaderProps) {
  const [user, setUser] = useState<string | null>(null);
  const [role, setRole] = useState<string | null>(null);
  const [isLoginOpen, setIsLoginOpen] = useState(false);
  const [usernameInput, setUsernameInput] = useState("");
  const [passwordInput, setPasswordInput] = useState("");
  const [loginError, setLoginError] = useState<string | null>(null);
  const cancelRef = useRef<HTMLButtonElement>(null);

  useEffect(() => {
    const savedUser = localStorage.getItem("janus_user");
    const savedRole = localStorage.getItem("janus_role");
    if (savedUser && savedRole) {
      setUser(savedUser);
      setRole(savedRole);
    }
  }, []);

  const handleLogin = async (e: React.FormEvent) => {
    e.preventDefault();
    setLoginError(null);
    try {
      const res = await fetch("/api/auth/login", {
        method: "POST",
        headers: { "content-type": "application/json" },
        body: JSON.stringify({ username: usernameInput, password: passwordInput })
      });
      if (!res.ok) {
        throw new Error(await res.text() || "Invalid credentials");
      }
      const data = await res.json();
      localStorage.setItem("janus_token", data.token);
      localStorage.setItem("janus_user", usernameInput);
      localStorage.setItem("janus_role", data.role);
      setUser(usernameInput);
      setRole(data.role);
      setIsLoginOpen(false);
      setUsernameInput("");
      setPasswordInput("");
    } catch (err) {
      setLoginError(err instanceof Error ? err.message : "Authentication failed");
    }
  };

  const handleLogout = () => {
    localStorage.removeItem("janus_token");
    localStorage.removeItem("janus_user");
    localStorage.removeItem("janus_role");
    setUser(null);
    setRole(null);
  };

  return (
    <header className="border-b border-[#dfe5dc] bg-white dark:border-[#2a3a30] dark:bg-[#1a2620]">
      <div className="mx-auto flex max-w-7xl items-center justify-between px-5 py-4">
        <div className="flex items-center gap-3">
          <div className="flex h-10 w-10 items-center justify-center rounded-md bg-[#17211c] text-white dark:bg-[#2a3a32]" aria-hidden="true">
            <ShieldCheck size={22} />
          </div>
          <div>
            <h1 className="text-xl font-semibold tracking-normal">Janus CryptoBOM</h1>
            <p className="text-sm text-[#697469] dark:text-[#8fa991]">Cryptographic exposure graph and PQC migration control</p>
          </div>
        </div>
        <div className="flex items-center gap-2 rounded-md border border-[#dfe5dc] bg-[#f7f8f5] px-3 py-2 text-sm dark:border-[#2a3a30] dark:bg-[#0d1210]">
          <Activity size={16} className="text-[#11845b] dark:text-[#3da06a]" aria-hidden="true" />
          <span>{error ? "API offline" : "Live controller"}</span>
        </div>

        <div className="flex items-center gap-3">
          {user ? (
            <div className="flex items-center gap-2 text-xs">
              <span className="text-[#697469] dark:text-[#8fa991]">
                Session: <strong className="dark:text-[#e8ede9]">{user}</strong> ({role})
              </span>
              <button
                onClick={handleLogout}
                className="text-red-600 hover:text-red-800 font-semibold flex items-center gap-0.5 dark:text-red-400 dark:hover:text-red-300"
                title="Logout"
                type="button"
                aria-label="Logout"
              >
                <LogOut size={12} aria-hidden="true" />
                Logout
              </button>
            </div>
          ) : (
            <button
              onClick={() => setIsLoginOpen(true)}
              className="flex h-9 items-center gap-1.5 rounded-md border border-[#dfe5dc] bg-white px-3 text-sm text-[#17211c] hover:bg-[#edf1ea] transition dark:border-[#2a3a30] dark:bg-[#1a2620] dark:text-[#e8ede9] dark:hover:bg-[#22302a]"
              type="button"
              aria-haspopup="dialog"
              aria-expanded={isLoginOpen}
            >
              <Lock size={14} aria-hidden="true" />
              Login
            </button>
          )}

          <a
            href="/api/report.html"
            target="_blank"
            rel="noreferrer"
            className="flex h-9 items-center gap-2 rounded-md border border-[#dfe5dc] bg-white px-3 text-sm text-[#17211c] hover:bg-[#edf1ea] dark:border-[#2a3a30] dark:bg-[#1a2620] dark:text-[#e8ede9] dark:hover:bg-[#22302a]"
            aria-label="Open HTML report (opens in new tab)"
          >
            <FileText size={16} aria-hidden="true" />
            Report
          </a>
        </div>
      </div>

      {/* Login Modal */}
      {isLoginOpen && (
        <FocusTrap active={isLoginOpen} onEscape={() => setIsLoginOpen(false)} initialFocusRef={cancelRef}>
          <div
            className="fixed inset-0 z-50 flex items-center justify-center bg-black/40 backdrop-blur-sm dark:bg-black/55"
            role="dialog"
            aria-modal="true"
            aria-labelledby="login-modal-title"
          >
            <div className="w-full max-w-sm rounded-md shadow-2xl p-6 border border-[#dfe5dc] bg-white dark:border-[#2a3a30] dark:bg-[#1a2620]">
              <h3 id="login-modal-title" className="text-base font-bold mb-4 text-[#17211c] dark:text-[#e8ede9]">
                Sign in to Janus Console
              </h3>
              {loginError && (
                <div className="text-xs text-red-600 mb-3 font-semibold bg-red-50 p-2 rounded dark:bg-[#2d1518] dark:text-red-400" role="alert">
                  {loginError}
                </div>
              )}
              <form onSubmit={handleLogin} className="space-y-4">
                <div>
                  <label htmlFor="login-username" className="block text-xs font-semibold text-[#697469] mb-1 dark:text-[#8fa991]">
                    Username
                  </label>
                  <input
                    id="login-username"
                    type="text"
                    value={usernameInput}
                    onChange={e => setUsernameInput(e.target.value)}
                    placeholder="admin / operator"
                    className="w-full rounded border border-[#dfe5dc] px-3 py-2 text-xs focus:outline-none focus:ring-1 dark:border-[#2a3a30] dark:bg-[#0d1210] dark:text-[#e8ede9] dark:placeholder-[#6b7e6f]"
                    required
                    autoComplete="username"
                  />
                </div>
                <div>
                  <label htmlFor="login-password" className="block text-xs font-semibold text-[#697469] mb-1 dark:text-[#8fa991]">
                    Password
                  </label>
                  <input
                    id="login-password"
                    type="password"
                    value={passwordInput}
                    onChange={e => setPasswordInput(e.target.value)}
                    placeholder="Password"
                    className="w-full rounded border border-[#dfe5dc] px-3 py-2 text-xs focus:outline-none focus:ring-1 dark:border-[#2a3a30] dark:bg-[#0d1210] dark:text-[#e8ede9] dark:placeholder-[#6b7e6f]"
                    required
                    autoComplete="current-password"
                  />
                </div>
                <div className="flex gap-2 justify-end pt-2">
                  <button
                    ref={cancelRef}
                    type="button"
                    onClick={() => setIsLoginOpen(false)}
                    className="rounded border border-[#dfe5dc] px-3 py-1.5 text-xs dark:border-[#2a3a30] dark:text-[#6b7e6f] dark:hover:bg-[#22302a]"
                  >
                    Cancel
                  </button>
                  <button
                    type="submit"
                    className="rounded bg-[#17211c] text-white px-4 py-1.5 text-xs font-bold dark:bg-[#2a3a32] dark:hover:bg-[#3a4a42]"
                  >
                    Sign In
                  </button>
                </div>
              </form>
            </div>
          </div>
        </FocusTrap>
      )}
    </header>
  );
}
