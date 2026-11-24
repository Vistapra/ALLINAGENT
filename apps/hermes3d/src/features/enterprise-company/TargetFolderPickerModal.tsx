"use client";

import { useCallback, useEffect, useState } from "react";
import {
  ArrowUp,
  CheckCircle2,
  Folder,
  FolderOpen,
  FolderPlus,
  HardDrive,
  Play,
  Trash2,
  Users,
  X,
} from "lucide-react";

export type PinnedFolderItem = {
  path: string;
  name: string;
  exists: boolean;
  stack: string[];
};

export type TargetFoldersState = {
  ok: boolean;
  active_folder: string | null;
  pinned_folders: PinnedFolderItem[];
  drives: string[];
  quick_roots: string[];
};

type BrowseResult = {
  ok: boolean;
  current_path: string;
  parent_path: string | null;
  drives: string[];
  directories: Array<{ name: string; path: string }>;
  files: Array<{ name: string; path: string; size_bytes: number }>;
};

export function useTargetFoldersLive() {
  const [state, setState] = useState<TargetFoldersState | null>(null);
  const [loading, setLoading] = useState(false);

  const refresh = useCallback(async () => {
    setLoading(true);
    try {
      const res = await fetch("/api/company/folders", { cache: "no-store" });
      if (res.ok) {
        const data = (await res.json()) as TargetFoldersState;
        setState(data);
      }
    } catch {
      // ignore offline
    } finally {
      setLoading(false);
    }
  }, []);

  const mutate = useCallback(
    async (action: "add" | "select" | "remove" | "clear", targetPath?: string | null) => {
      const res = await fetch("/api/company/folders", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ action, path: targetPath ?? "" }),
      });
      const data = await res.json();
      if (!res.ok) {
        throw new Error(data?.error || "Gagal menyimpan folder target.");
      }
      setState(data as TargetFoldersState);
      if (typeof window !== "undefined") {
        window.dispatchEvent(new CustomEvent("enterprise-office:folders-updated", { detail: data }));
      }
      return data as TargetFoldersState;
    },
    []
  );

  useEffect(() => {
    void refresh();
    const onSync = (event: Event) => {
      const custom = event as CustomEvent<TargetFoldersState>;
      if (custom.detail?.ok) {
        setState(custom.detail);
      } else {
        void refresh();
      }
    };
    window.addEventListener("enterprise-office:folders-updated", onSync);
    return () => window.removeEventListener("enterprise-office:folders-updated", onSync);
  }, [refresh]);

  return { state, loading, refresh, mutate };
}

export function TargetFolderPickerModal({
  open,
  onClose,
  onAnalyzeFolder,
  onStartMeetingForFolder,
}: {
  open: boolean;
  onClose: () => void;
  onAnalyzeFolder?: (folderPath: string) => void;
  onStartMeetingForFolder?: (folderPath: string) => void;
}) {
  const { state, mutate, refresh } = useTargetFoldersLive();
  const [customPathInput, setCustomPathInput] = useState("");
  const [browsePath, setBrowsePath] = useState(
    () => state?.active_folder || state?.quick_roots?.[0] || ""
  );
  const [browseData, setBrowseData] = useState<BrowseResult | null>(null);
  const [browseLoading, setBrowseLoading] = useState(false);
  const [banner, setBanner] = useState<{ kind: "ok" | "err"; text: string } | null>(null);

  const loadDirectory = useCallback(async (dirPath: string) => {
    setBrowseLoading(true);
    setBanner(null);
    try {
      const res = await fetch(
        `/api/company/folders/browse?path=${encodeURIComponent(dirPath)}`,
        { cache: "no-store" }
      );
      const data = await res.json();
      if (!res.ok) {
        throw new Error(data?.error || "Tidak dapat membuka direktori ini.");
      }
      setBrowseData(data as BrowseResult);
      setBrowsePath((data as BrowseResult).current_path || dirPath);
    } catch (err) {
      setBanner({
        kind: "err",
        text: err instanceof Error ? err.message : "Gagal memuat isi folder.",
      });
    } finally {
      setBrowseLoading(false);
    }
  }, []);

  useEffect(() => {
    if (!open) return;
    void refresh();
  }, [open, refresh]);

  const initialBrowseTarget = state?.active_folder || state?.quick_roots?.[0] || "";
  useEffect(() => {
    if (!open) return;
    setBrowsePath(initialBrowseTarget);
    void loadDirectory(initialBrowseTarget);
  }, [open, loadDirectory, initialBrowseTarget]);

  if (!open) return null;

  const handleAddCustomPath = async (e: React.FormEvent) => {
    e.preventDefault();
    const trimmed = customPathInput.trim();
    if (!trimmed) return;
    try {
      const updated = await mutate("add", trimmed);
      setCustomPathInput("");
      setBanner({
        kind: "ok",
        text: `Folder target aktif disetel ke: ${updated.active_folder}`,
      });
      if (updated.active_folder) {
        void loadDirectory(updated.active_folder);
      }
    } catch (err) {
      setBanner({
        kind: "err",
        text: err instanceof Error ? err.message : "Path tidak valid atau dibatasi.",
      });
    }
  };

  const handleSelectFolder = async (folderPath: string) => {
    try {
      const updated = await mutate("add", folderPath);
      setBanner({
        kind: "ok",
        text: `Folder target dipilih: ${updated.active_folder}`,
      });
    } catch (err) {
      setBanner({
        kind: "err",
        text: err instanceof Error ? err.message : "Gagal memilih folder.",
      });
    }
  };

  const activeFolder = state?.active_folder || null;

  return (
    <div
      data-testid="target-folder-picker-modal"
      className="pointer-events-auto fixed inset-0 z-50 flex items-center justify-center bg-black/70 p-4 backdrop-blur-sm"
    >
      <div className="flex max-h-[88vh] w-full max-w-3xl flex-col overflow-hidden rounded-xl border border-cyan-500/35 bg-[#060d15]/98 text-slate-100 shadow-2xl">
        {/* Header */}
        <div className="flex items-center justify-between border-b border-cyan-500/20 px-4 py-3">
          <div className="flex items-center gap-2">
            <FolderOpen className="h-4 w-4 text-cyan-300" />
            <div>
              <div className="font-mono text-xs font-bold uppercase tracking-wider text-cyan-200">
                Pilih / Tambah Folder Target Workspace
              </div>
              <div className="text-[11px] text-slate-400">
                Pilih folder workspace atau direktori proyek Anda (mis. `/workspaces/my-project`) untuk dianalisis agen atau dibahas bersama 11 agen di Ruang Meeting.
              </div>
            </div>
          </div>
          <button
            type="button"
            onClick={onClose}
            className="rounded border border-white/15 bg-white/5 p-1.5 text-slate-300 hover:border-cyan-400/50 hover:text-white"
            aria-label="Tutup pemilih folder"
          >
            <X className="h-4 w-4" />
          </button>
        </div>

        <div className="min-h-0 flex-1 overflow-y-auto p-4 space-y-4">
          {banner ? (
            <div
              className={`rounded-lg border px-3 py-2 font-mono text-[11px] ${
                banner.kind === "ok"
                  ? "border-emerald-400/40 bg-emerald-500/15 text-emerald-100"
                  : "border-rose-400/45 bg-rose-500/15 text-rose-100"
              }`}
            >
              {banner.text}
            </div>
          ) : null}

          {/* Manual Path Input */}
          <form onSubmit={handleAddCustomPath} className="space-y-1.5">
            <label className="block font-mono text-[10px] uppercase tracking-wider text-cyan-300/80">
              Ketik atau Tempel Path Folder Proyek / Workspace Anda
            </label>
            <div className="flex gap-2">
              <input
                type="text"
                data-testid="folder-custom-path-input"
                value={customPathInput}
                onChange={(e) => setCustomPathInput(e.target.value)}
                placeholder="/workspaces/my-project"
                className="min-w-0 flex-1 rounded-lg border border-white/15 bg-black/55 px-3 py-2 font-mono text-xs text-white outline-none focus:border-cyan-400"
              />
              <button
                type="submit"
                data-testid="folder-add-submit-btn"
                className="inline-flex shrink-0 items-center gap-1.5 rounded-lg border border-cyan-400/50 bg-cyan-500/20 px-3 py-2 font-mono text-xs font-semibold text-cyan-100 hover:bg-cyan-500/30"
              >
                <FolderPlus className="h-3.5 w-3.5" />
                <span>Tambah & Pilih</span>
              </button>
            </div>
          </form>

          {/* Active Folder Action Box */}
          {activeFolder ? (
            <div
              data-testid="active-target-folder-card"
              className="flex flex-wrap items-center justify-between gap-2 rounded-lg border border-emerald-400/35 bg-emerald-500/10 px-3 py-2.5"
            >
              <div className="min-w-0">
                <div className="flex items-center gap-1.5 font-mono text-[10px] uppercase tracking-wider text-emerald-300">
                  <CheckCircle2 className="h-3.5 w-3.5" />
                  <span>Folder Target Aktif Saat Ini</span>
                </div>
                <div className="mt-0.5 truncate font-mono text-xs font-semibold text-white">
                  {activeFolder}
                </div>
              </div>
              <div className="flex flex-wrap items-center gap-1.5">
                {onAnalyzeFolder ? (
                  <button
                    type="button"
                    data-testid="modal-analyze-active-folder-btn"
                    onClick={() => {
                      onAnalyzeFolder(activeFolder);
                      onClose();
                    }}
                    className="inline-flex items-center gap-1 rounded border border-emerald-400/50 bg-emerald-500/25 px-2.5 py-1.5 font-mono text-[11px] font-semibold text-emerald-100 hover:bg-emerald-500/35"
                  >
                    <Play className="h-3 w-3" />
                    <span>Analisis Sekarang</span>
                  </button>
                ) : null}
                {onStartMeetingForFolder ? (
                  <button
                    type="button"
                    data-testid="modal-meeting-active-folder-btn"
                    onClick={() => {
                      onStartMeetingForFolder(activeFolder);
                      onClose();
                    }}
                    className="inline-flex items-center gap-1 rounded border border-cyan-400/50 bg-cyan-500/25 px-2.5 py-1.5 font-mono text-[11px] font-semibold text-cyan-100 hover:bg-cyan-500/35"
                  >
                    <Users className="h-3 w-3" />
                    <span>Rapat 11 Agen</span>
                  </button>
                ) : null}
                <button
                  type="button"
                  onClick={() => void mutate("clear")}
                  className="rounded border border-white/15 bg-black/40 px-2 py-1.5 font-mono text-[10px] text-slate-300 hover:text-white"
                >
                  Lepas Pilihan
                </button>
              </div>
            </div>
          ) : null}

          {/* Pinned / Saved Target Folders */}
          {(state?.pinned_folders?.length ?? 0) > 0 ? (
            <div>
              <div className="mb-1.5 font-mono text-[10px] uppercase tracking-wider text-slate-400">
                Daftar Folder Tersimpan (Klik untuk Memilih)
              </div>
              <div className="grid grid-cols-1 gap-1.5 sm:grid-cols-2">
                {state!.pinned_folders.map((item) => {
                  const isActive = activeFolder === item.path;
                  return (
                    <div
                      key={item.path}
                      className={`flex items-center justify-between gap-2 rounded-lg border px-2.5 py-2 ${
                        isActive
                          ? "border-cyan-400/55 bg-cyan-500/15"
                          : "border-white/10 bg-white/[0.03] hover:border-white/25"
                      }`}
                    >
                      <button
                        type="button"
                        onClick={() => {
                          void handleSelectFolder(item.path);
                          void loadDirectory(item.path);
                        }}
                        className="min-w-0 flex-1 text-left"
                      >
                        <div className="truncate font-mono text-xs font-semibold text-white">
                          {item.name}
                        </div>
                        <div className="truncate font-mono text-[10px] text-slate-400">
                          {item.path}
                        </div>
                      </button>
                      <button
                        type="button"
                        onClick={() => void mutate("remove", item.path)}
                        className="rounded p-1 text-slate-400 hover:bg-rose-500/20 hover:text-rose-200"
                        title="Hapus dari daftar tersimpan"
                      >
                        <Trash2 className="h-3.5 w-3.5" />
                      </button>
                    </div>
                  );
                })}
              </div>
            </div>
          ) : null}

          {/* Visual Directory Explorer */}
          <div className="rounded-xl border border-white/12 bg-black/40 p-3">
            <div className="flex flex-wrap items-center justify-between gap-2 border-b border-white/10 pb-2.5">
              <div className="flex flex-wrap items-center gap-1">
                {(state?.quick_roots ?? []).map((root) => (
                  <button
                    key={root}
                    type="button"
                    onClick={() => void loadDirectory(root)}
                    className={`inline-flex items-center gap-1 rounded border px-2 py-1 font-mono text-[10px] ${
                      browsePath === root
                        ? "border-cyan-400/50 bg-cyan-500/20 text-cyan-100"
                        : "border-white/12 bg-white/5 text-slate-300 hover:text-white"
                    }`}
                  >
                    <HardDrive className="h-3 w-3" />
                    <span>{root}</span>
                  </button>
                ))}
              </div>
              {browseData?.current_path ? (
                <button
                  type="button"
                  data-testid="explorer-select-current-dir-btn"
                  onClick={() => void handleSelectFolder(browseData.current_path)}
                  className="rounded border border-amber-400/45 bg-amber-500/20 px-2.5 py-1 font-mono text-[10px] font-semibold text-amber-100 hover:bg-amber-500/30"
                >
                  ✓ Gunakan Folder Ini ({browseData.current_path})
                </button>
              ) : null}
            </div>

            <div className="mt-2 flex items-center justify-between gap-2 font-mono text-[11px] text-cyan-200">
              <span className="truncate">
                📂 Lokasi: {browseData?.current_path || browsePath || "(Pilih Folder Workspace)"}
              </span>
              {browseData?.parent_path !== null && browseData?.current_path ? (
                <button
                  type="button"
                  onClick={() => void loadDirectory(browseData.parent_path || "")}
                  className="inline-flex shrink-0 items-center gap-1 rounded border border-white/15 bg-white/5 px-2 py-0.5 text-[10px] text-slate-200 hover:border-cyan-400/40"
                >
                  <ArrowUp className="h-3 w-3" />
                  <span>Naik 1 Level</span>
                </button>
              ) : null}
            </div>

            {browseLoading ? (
              <div className="py-6 text-center font-mono text-xs text-slate-400">
                Memuat daftar folder...
              </div>
            ) : (
              <div className="mt-2 max-h-56 overflow-y-auto divide-y divide-white/5 rounded border border-white/8 bg-[#050a10]">
                {(browseData?.directories ?? []).map((dir) => (
                  <div
                    key={dir.path}
                    className="flex items-center justify-between gap-2 px-3 py-1.5 hover:bg-white/[0.04]"
                  >
                    <button
                      type="button"
                      onClick={() => void loadDirectory(dir.path)}
                      className="flex min-w-0 flex-1 items-center gap-2 text-left font-mono text-xs text-slate-100 hover:text-cyan-200"
                    >
                      <Folder className="h-3.5 w-3.5 shrink-0 text-amber-300" />
                      <span className="truncate">{dir.name}/</span>
                    </button>
                    <div className="flex shrink-0 items-center gap-1">
                      <button
                        type="button"
                        onClick={() => void handleSelectFolder(dir.path)}
                        className="rounded border border-cyan-500/30 bg-cyan-500/10 px-2 py-0.5 font-mono text-[10px] text-cyan-200 hover:bg-cyan-500/25"
                      >
                        Pilih
                      </button>
                      {onAnalyzeFolder ? (
                        <button
                          type="button"
                          onClick={() => {
                            void handleSelectFolder(dir.path).then(() => {
                              onAnalyzeFolder(dir.path);
                              onClose();
                            });
                          }}
                          className="rounded border border-emerald-500/35 bg-emerald-500/15 px-2 py-0.5 font-mono text-[10px] text-emerald-200 hover:bg-emerald-500/25"
                        >
                          Analisis
                        </button>
                      ) : null}
                    </div>
                  </div>
                ))}
                {(browseData?.files ?? []).slice(0, 25).map((file) => (
                  <div
                    key={file.path}
                    className="flex items-center justify-between gap-2 px-3 py-1 font-mono text-[11px] text-slate-400"
                  >
                    <span className="truncate">📄 {file.name}</span>
                    <span className="shrink-0 text-[10px] text-slate-500">
                      {(file.size_bytes / 1024).toFixed(1)} KB
                    </span>
                  </div>
                ))}
                {(browseData?.directories?.length ?? 0) === 0 &&
                (browseData?.files?.length ?? 0) === 0 ? (
                  <div className="py-4 text-center font-mono text-xs text-slate-500">
                    Folder kosong.
                  </div>
                ) : null}
              </div>
            )}
          </div>
        </div>
      </div>
    </div>
  );
}
