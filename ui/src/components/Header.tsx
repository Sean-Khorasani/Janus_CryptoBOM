import { Activity, FileText, ShieldCheck } from "lucide-react";

interface HeaderProps {
  error: string;
}

export function Header({ error }: HeaderProps) {
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
    </header>
  );
}
