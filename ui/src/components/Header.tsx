import { Activity, FileText, ShieldCheck, Lock, LogOut } from "lucide-react";
import { useState, useEffect } from "react";

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
    <header className="border-b border-[#dfe5dc] bg-white">
      <div className="mx-auto flex max-w-7xl items-center justify-between px-5 py-4">
        <div className="flex items-center gap-3">
          <div className="flex h-10 w-10 items-center justify-center rounded-md bg-[#17211c] text-white">
            <ShieldCheck size={22} />
          </div>
          <div>
            <h1 className="text-xl font-semibold tracking-normal">Janus CryptoBOM</h1>
            <p className="text-sm text-[#697469]">Cryptographic exposure graph and PQC migration control</p>
          </div>
        </div>
        <div className="flex items-center gap-2 rounded-md border border-[#dfe5dc] bg-[#f7f8f5] px-3 py-2 text-sm">
          <Activity size={16} className="text-[#11845b]" />
          <span>{error ? "API offline" : "Live controller"}</span>
        </div>
        
        <div className="flex items-center gap-3">
          {user ? (
            <div className="flex items-center gap-2 text-xs">
              <span className="text-[#697469]">Session: <strong>{user}</strong> ({role})</span>
              <button
                onClick={handleLogout}
                className="text-red-600 hover:text-red-800 font-semibold flex items-center gap-0.5"
                title="Logout"
              >
                <LogOut size={12} />
                Logout
              </button>
            </div>
          ) : (
            <button
              onClick={() => setIsLoginOpen(true)}
              className="flex h-9 items-center gap-1.5 rounded-md border border-[#dfe5dc] bg-white px-3 text-sm text-[#17211c] hover:bg-[#edf1ea] transition"
            >
              <Lock size={14} />
              Login
            </button>
          )}

          <a
            href="/api/report.html"
            target="_blank"
            rel="noreferrer"
            className="flex h-9 items-center gap-2 rounded-md border border-[#dfe5dc] bg-white px-3 text-sm text-[#17211c] hover:bg-[#edf1ea]"
          >
            <FileText size={16} />
            Report
          </a>
        </div>
      </div>

      {/* Login Modal */}
      {isLoginOpen && (
        <div className="fixed inset-0 z-50 flex items-center justify-center bg-black/40 backdrop-blur-sm">
          <div className="w-full max-w-sm bg-white rounded-md shadow-2xl p-6 border border-[#dfe5dc]">
            <h3 className="text-base font-bold mb-4 text-[#17211c]">Sign in to Janus Console</h3>
            {loginError && (
              <div className="text-xs text-red-600 mb-3 font-semibold bg-red-50 p-2 rounded">
                {loginError}
              </div>
            )}
            <form onSubmit={handleLogin} className="space-y-4">
              <div>
                <label className="block text-xs font-semibold text-[#697469] mb-1">Username</label>
                <input
                  type="text"
                  value={usernameInput}
                  onChange={e => setUsernameInput(e.target.value)}
                  placeholder="admin / operator"
                  className="w-full rounded border border-[#dfe5dc] px-3 py-2 text-xs focus:outline-none focus:ring-1"
                  required
                />
              </div>
              <div>
                <label className="block text-xs font-semibold text-[#697469] mb-1">Password</label>
                <input
                  type="password"
                  value={passwordInput}
                  onChange={e => setPasswordInput(e.target.value)}
                  placeholder="Password"
                  className="w-full rounded border border-[#dfe5dc] px-3 py-2 text-xs focus:outline-none focus:ring-1"
                  required
                />
              </div>
              <div className="flex gap-2 justify-end pt-2">
                <button
                  type="button"
                  onClick={() => setIsLoginOpen(false)}
                  className="rounded border border-[#dfe5dc] px-3 py-1.5 text-xs"
                >
                  Cancel
                </button>
                <button
                  type="submit"
                  className="rounded bg-[#17211c] text-white px-4 py-1.5 text-xs font-bold"
                >
                  Sign In
                </button>
              </div>
            </form>
          </div>
        </div>
      )}
    </header>
  );
}
